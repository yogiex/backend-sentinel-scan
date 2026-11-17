package postgres

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// errNoDB is returned when a repository was built without a connection.
var errNoDB = apperr.ErrInternalServer

// resolvedTicketStatuses are the states in which a ticket no longer needs a
// fix, so it cannot be overdue.
var resolvedTicketStatuses = []string{
	string(entity.TicketStatusFixed),
	string(entity.TicketStatusVerified),
	string(entity.TicketStatusWontFix),
}

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
	priority := t.Priority
	if priority == "" {
		priority = entity.PriorityFromSeverity(severity)
	}
	m := &Ticket{
		CreatedBy:   t.CreatedBy,
		AssignedTo:  t.AssignedTo,
		ScanID:      t.ScanID,
		FindingID:   t.FindingID,
		Title:       t.Title,
		Description: t.Description,
		Severity:    severity,
		Priority:    string(priority),
		Status:      status,
		DueDate:     t.DueDate,
		ClosedAt:    t.ClosedAt,
		UpdatedBy:   t.UpdatedBy,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	t.ID = m.ID
	t.Code = entity.FormatTicketCode(m.ID)
	t.Severity = severity
	t.Priority = priority
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
		"priority":    string(t.Priority),
		"status":      string(t.Status),
		"assigned_to": t.AssignedTo,
		"due_date":    t.DueDate,
		"closed_at":   t.ClosedAt,
		"updated_by":  t.UpdatedBy,
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

// FindByIDOwned resolves a ticket only if the user created it or was assigned
// to it: a foreign ticket is indistinguishable from a missing one.
func (r *ticketRepository) FindByIDOwned(ctx context.Context, id, ownerID uint) (*entity.Ticket, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var m Ticket
	err := r.db.WithContext(ctx).
		Where("id = ? AND (created_by = ? OR assigned_to = ?)", id, ownerID, ownerID).
		First(&m).Error
	if err != nil {
		return nil, mapGormError(err)
	}
	return m.toEntity(), nil
}

func (r *ticketRepository) List(ctx context.Context, filter repository.TicketFilter) ([]*entity.Ticket, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	query := applyTicketFilter(r.db.WithContext(ctx).Model(&Ticket{}), filter)
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

func (r *ticketRepository) Count(ctx context.Context, filter repository.TicketFilter) (int64, error) {
	if r.db == nil {
		return 0, errNoDB
	}
	query := applyTicketFilter(r.db.WithContext(ctx).Model(&Ticket{}), filter)
	var total int64
	return total, query.Count(&total).Error
}

// Stats returns the board overview. Status and priority filters are ignored on
// purpose: the breakdown is what those filters are chosen from, so applying
// them would return a single non-zero bar.
func (r *ticketRepository) Stats(ctx context.Context, filter repository.TicketFilter) (*entity.TicketStats, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	base := filter
	base.Status = ""
	base.Priority = ""
	base.OverdueOnly = false

	stats := &entity.TicketStats{
		ByStatus:   map[string]int64{},
		ByPriority: map[string]int64{},
	}
	for _, status := range []entity.TicketStatus{
		entity.TicketStatusOpen, entity.TicketStatusInProgress, entity.TicketStatusFixed,
		entity.TicketStatusVerified, entity.TicketStatusWontFix,
	} {
		stats.ByStatus[string(status)] = 0
	}
	for _, priority := range []entity.TicketPriority{
		entity.TicketPriorityCritical, entity.TicketPriorityHigh,
		entity.TicketPriorityMedium, entity.TicketPriorityLow,
	} {
		stats.ByPriority[string(priority)] = 0
	}

	var statusRows []struct {
		Status string
		Total  int64
	}
	query := applyTicketFilter(r.db.WithContext(ctx).Model(&Ticket{}), base)
	if err := query.Select("status, count(*) AS total").Group("status").Scan(&statusRows).Error; err != nil {
		return nil, err
	}
	for _, row := range statusRows {
		stats.ByStatus[row.Status] = row.Total
		stats.Total += row.Total
	}

	var priorityRows []struct {
		Priority string
		Total    int64
	}
	query = applyTicketFilter(r.db.WithContext(ctx).Model(&Ticket{}), base)
	if err := query.Select("priority, count(*) AS total").Group("priority").Scan(&priorityRows).Error; err != nil {
		return nil, err
	}
	for _, row := range priorityRows {
		stats.ByPriority[row.Priority] = row.Total
	}

	overdue := base
	overdue.OverdueOnly = true
	query = applyTicketFilter(r.db.WithContext(ctx).Model(&Ticket{}), overdue)
	if err := query.Count(&stats.Overdue).Error; err != nil {
		return nil, err
	}
	return stats, nil
}

func (r *ticketRepository) CreateComment(ctx context.Context, c *entity.TicketComment) error {
	if r.db == nil {
		return errNoDB
	}
	m := &TicketComment{
		TicketID: c.TicketID,
		AuthorID: c.AuthorID,
		Message:  c.Message,
	}
	if err := r.db.WithContext(ctx).Create(m).Error; err != nil {
		return err
	}
	c.ID = m.ID
	c.CreatedAt = m.CreatedAt
	return nil
}

func (r *ticketRepository) ListComments(ctx context.Context, ticketID uint) ([]*entity.TicketComment, error) {
	if r.db == nil {
		return nil, errNoDB
	}
	var rows []TicketComment
	if err := r.db.WithContext(ctx).
		Where("ticket_id = ?", ticketID).
		Order("created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*entity.TicketComment, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].toEntity())
	}
	return out, nil
}

// applyTicketFilter builds the WHERE clause shared by list, count, and stats so
// the three can never disagree about which tickets they describe.
func applyTicketFilter(query *gorm.DB, filter repository.TicketFilter) *gorm.DB {
	if filter.Status != "" {
		query = query.Where("status = ?", string(filter.Status))
	}
	if filter.Priority != "" {
		query = query.Where("priority = ?", string(filter.Priority))
	}
	if filter.Severity != "" {
		query = query.Where("severity = ?", filter.Severity)
	}
	if filter.ScanID != 0 {
		query = query.Where("scan_id = ?", filter.ScanID)
	}
	if filter.CreatedBy != 0 {
		query = query.Where("created_by = ?", filter.CreatedBy)
	}
	if filter.AssignedTo != 0 {
		query = query.Where("assigned_to = ?", filter.AssignedTo)
	}
	if filter.VisibleTo != 0 {
		query = query.Where("created_by = ? OR assigned_to = ?", filter.VisibleTo, filter.VisibleTo)
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		// LOWER() instead of ILIKE so the same query works on Postgres and on the
		// SQLite used by repository tests.
		query = query.Where("LOWER(title) LIKE ?", "%"+strings.ToLower(search)+"%")
	}
	if filter.OverdueOnly {
		query = query.
			Where("due_date IS NOT NULL AND due_date < ?", time.Now().UTC()).
			Where("status NOT IN ?", resolvedTicketStatuses)
	}
	return query
}
