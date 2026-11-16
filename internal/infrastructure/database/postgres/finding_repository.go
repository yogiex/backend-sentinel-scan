package postgres

import (
	"context"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
)

type findingRepository struct{ db *gorm.DB }

// NewFindingRepository returns a Postgres-backed FindingRepository.
func NewFindingRepository(db *gorm.DB) repository.FindingRepository {
	return &findingRepository{db: db}
}

func (r *findingRepository) Create(ctx context.Context, f *entity.Finding) error {
	if r.db == nil {
		return errNoDB
	}
	m := findingFromEntity(f)
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	f.ID = m.ID
	f.CreatedAt = m.CreatedAt
	return nil
}

// CreateBatch inserts findings in chunks, de-duplicating identical
// (target, template) results so a retried task cannot inflate the report.
func (r *findingRepository) CreateBatch(ctx context.Context, findings []*entity.Finding) error {
	if r.db == nil {
		return errNoDB
	}
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	models := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Target + "\x00" + f.TemplateID
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		models = append(models, *findingFromEntity(f))
	}
	if len(models) == 0 {
		return nil
	}
	// The conflict target must name the partial unique index and repeat its
	// predicate, otherwise Postgres cannot infer which index to use and the
	// whole clause is either ignored or rejected.
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "scan_id"}, {Name: "target"}, {Name: "template_id"},
			},
			TargetWhere: clause.Where{Exprs: []clause.Expression{
				clause.Eq{Column: clause.Column{Name: "deleted_at"}, Value: nil},
			}},
			DoNothing: true,
		}).CreateInBatches(&models, 500).Error
	})
}

func (r *findingRepository) FindByScanID(ctx context.Context, scanID uint) ([]*entity.Finding, error) {
	return r.FindByScanIDLimit(ctx, scanID, 500)
}

func (r *findingRepository) FindByScanIDLimit(ctx context.Context, scanID uint, limit int) ([]*entity.Finding, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	var rows []Finding
	if err := r.db.WithContext(ctx).
		Where("scan_id = ?", scanID).
		Order("created_at ASC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*entity.Finding, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toEntity())
	}
	return out, nil
}

func (r *findingRepository) FindByID(ctx context.Context, id uint) (*entity.Finding, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m Finding
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}
