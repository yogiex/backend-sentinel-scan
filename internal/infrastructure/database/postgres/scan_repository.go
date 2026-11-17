package postgres

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

const (
	defaultPageSize = 20
	maxPageSize     = 100
)

// legalTransitions is the scan state machine. Terminal states have no exits.
var legalTransitions = map[entity.ScanStatus][]entity.ScanStatus{
	entity.ScanStatusPending:   {entity.ScanStatusRunning, entity.ScanStatusCancelled, entity.ScanStatusFailed},
	entity.ScanStatusRunning:   {entity.ScanStatusCompleted, entity.ScanStatusFailed, entity.ScanStatusCancelled},
	entity.ScanStatusCompleted: {},
	entity.ScanStatusFailed:    {},
	entity.ScanStatusCancelled: {},
}

type scanRepository struct{ db *gorm.DB }

// NewScanRepository returns a Postgres-backed ScanRepository.
func NewScanRepository(db *gorm.DB) repository.ScanRepository { return &scanRepository{db: db} }

func (r *scanRepository) ready() error {
	if r.db == nil {
		return apperr.ErrInternalServer
	}
	return nil
}

func (r *scanRepository) Create(ctx context.Context, scan *entity.ScanJob) error {
	if err := r.ready(); err != nil {
		return err
	}
	if len(scan.Targets) == 0 {
		return apperr.NewAppError("INVALID_INPUT", "At least one target is required", 400)
	}
	m := scanFromEntity(scan)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	scan.ID = m.ID
	scan.Status = entity.ScanStatus(m.Status)
	scan.CreatedAt = m.CreatedAt
	scan.UpdatedAt = m.UpdatedAt
	if scan.Progress == nil {
		scan.Progress = &entity.ScanProgress{}
	}
	return nil
}

func (r *scanRepository) FindByID(ctx context.Context, id uint) (*entity.ScanJob, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	var m ScanJob
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

func (r *scanRepository) FindByIDOwned(ctx context.Context, id, ownerID uint) (*entity.ScanJob, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	var m ScanJob
	err := r.db.WithContext(ctx).Where("id = ? AND created_by = ?", id, ownerID).First(&m).Error
	if err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

// UpdateStatus applies a state transition with compare-and-swap semantics so
// two workers cannot both finish the same scan.
func (r *scanRepository) UpdateStatus(ctx context.Context, id uint, status entity.ScanStatus) error {
	if err := r.ready(); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current ScanJob
		if err := tx.Select("id", "status").First(&current, id).Error; err != nil {
			return mapGormError(err)
		}
		from := entity.ScanStatus(current.Status)
		if from == status {
			return nil
		}
		allowed := false
		for _, next := range legalTransitions[from] {
			if next == status {
				allowed = true
				break
			}
		}
		if !allowed {
			return apperr.NewAppError("CONFLICT", "Illegal status transition", 409)
		}
		res := tx.Model(&ScanJob{}).
			Where("id = ? AND status = ?", id, current.Status).
			Update("status", string(status))
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return apperr.ErrConflict
		}
		return nil
	})
}

// UpdateProgress writes absolute counters in a single statement.
func (r *scanRepository) UpdateProgress(ctx context.Context, id uint, progress *entity.ScanProgress) error {
	if err := r.ready(); err != nil {
		return err
	}
	if progress == nil {
		return nil
	}
	res := r.db.WithContext(ctx).Model(&ScanJob{}).Where("id = ?", id).Updates(map[string]any{
		"total_tasks":       progress.TotalTasks,
		"completed_tasks":   progress.Completed,
		"failed_tasks":      progress.Failed,
		"in_progress_tasks": progress.InProgress,
		"phase":             progress.Phase,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *scanRepository) SetTruncated(ctx context.Context, id uint) error {
	if err := r.ready(); err != nil {
		return err
	}
	res := r.db.WithContext(ctx).Model(&ScanJob{}).Where("id = ?", id).Update("truncated", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *scanRepository) List(ctx context.Context, filter repository.ScanFilter) ([]*entity.ScanJob, error) {
	if err := r.ready(); err != nil {
		return nil, err
	}
	query := r.db.WithContext(ctx).Model(&ScanJob{})
	if filter.CreatedBy != 0 {
		query = query.Where("created_by = ?", filter.CreatedBy)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	page, size := normalizePage(filter.Page, filter.PageSize)
	var rows []ScanJob
	if err := query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*entity.ScanJob, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toEntity())
	}
	return out, nil
}

func (r *scanRepository) Count(ctx context.Context, filter repository.ScanFilter) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	query := r.db.WithContext(ctx).Model(&ScanJob{})
	if filter.CreatedBy != 0 {
		query = query.Where("created_by = ?", filter.CreatedBy)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	var total int64
	return total, query.Count(&total).Error
}

func (r *scanRepository) Delete(ctx context.Context, id uint) error {
	if err := r.ready(); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("scan_id = ?", id).Delete(&Finding{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&ScanJob{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return apperr.ErrNotFound
		}
		return nil
	})
}

// ── shared helpers ──────────────────────────────────────────

func normalizePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	return page, size
}

func mapGormError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apperr.ErrNotFound
	}
	return err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint")
}
