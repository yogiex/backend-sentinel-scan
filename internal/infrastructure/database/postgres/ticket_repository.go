package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// errNoDB is returned when a repository was built without a connection.
var errNoDB = apperr.ErrInternalServer

type ticketRepository struct{ db *gorm.DB }

// NewTicketRepository returns a Postgres-backed TicketRepository.
func NewTicketRepository(db *gorm.DB) repository.TicketRepository { return &ticketRepository{db: db} }

func (r *ticketRepository) Create(ctx context.Context, t *entity.Ticket) error {
	if r.db == nil {
		return errNoDB
	}
	status := string(t.Status)
	if status == "" {
		status = string(entity.TicketStatusOpen)
	}
	severity := t.Severity
	if severity == "" {
		severity = "info"
	}
	m := &Ticket{
		CreatedBy:   t.CreatedBy,
		AssignedTo:  t.AssignedTo,
		FindingID:   t.FindingID,
		Title:       t.Title,
		Description: t.Description,
		Severity:    severity,
		Status:      status,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	t.ID = m.ID
	t.Status = entity.TicketStatus(m.Status)
	t.CreatedAt = m.CreatedAt
	t.UpdatedAt = m.UpdatedAt
	return nil
}

func (r *ticketRepository) Update(ctx context.Context, t *entity.Ticket) error {
	if r.db == nil {
		return errNoDB
	}
	updates := map[string]any{
		"title":       t.Title,
		"description": t.Description,
		"severity":    t.Severity,
		"status":      string(t.Status),
		"assigned_to": t.AssignedTo,
	}
	res := r.db.WithContext(ctx).Model(&Ticket{}).Where("id = ?", t.ID).Updates(updates)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return apperr.ErrNotFound
	}
	return nil
}

func (r *ticketRepository) FindByID(ctx context.Context, id uint) (*entity.Ticket, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m Ticket
	if err := r.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

func (r *ticketRepository) List(ctx context.Context, filter repository.TicketFilter) ([]*entity.Ticket, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	query := r.db.WithContext(ctx).Model(&Ticket{})
	if filter.Status != "" {
		query = query.Where("status = ?", string(filter.Status))
	}
	if filter.CreatedBy != 0 {
		query = query.Where("created_by = ?", filter.CreatedBy)
	}
	if filter.AssignedTo != 0 {
		query = query.Where("assigned_to = ?", filter.AssignedTo)
	}
	if filter.Severity != "" {
		query = query.Where("severity = ?", filter.Severity)
	}
	page, size := normalizePage(filter.Page, filter.PageSize)
	var rows []Ticket
	if err := query.Order("created_at DESC").Offset((page - 1) * size).Limit(size).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*entity.Ticket, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toEntity())
	}
	return out, nil
}
