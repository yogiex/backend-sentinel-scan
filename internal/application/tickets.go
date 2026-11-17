package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

const (
	maxTicketTitleLen       = 200
	maxTicketDescriptionLen = 10000
	maxTicketCommentLen     = 2000
	maxTicketSearchLen      = 100
)

// ticketSLA is how long each priority may wait before it is overdue. It is the
// default due date, not a deadline the caller is forced to accept.
var ticketSLA = map[entity.TicketPriority]time.Duration{
	entity.TicketPriorityCritical: 3 * 24 * time.Hour,
	entity.TicketPriorityHigh:     7 * 24 * time.Hour,
	entity.TicketPriorityMedium:   14 * 24 * time.Hour,
	entity.TicketPriorityLow:      30 * 24 * time.Hour,
}

// TicketService turns findings into remediation tickets and moves them through
// their lifecycle.
//
// Two rules are enforced here rather than trusted to the caller: a ticket's
// severity and scan come from the finding, never from the request, and an
// assignee sees exactly the tickets they created or were given.
type TicketService struct {
	tickets  repository.TicketRepository
	findings repository.FindingRepository
	scans    repository.ScanRepository
	users    repository.UserRepository
}

func NewTicketService(
	tickets repository.TicketRepository,
	findings repository.FindingRepository,
	scans repository.ScanRepository,
	users repository.UserRepository,
) *TicketService {
	return &TicketService{tickets: tickets, findings: findings, scans: scans, users: users}
}

// CreateTicketInput is what a caller may choose when creating a ticket. Finding
// ID is the only source of severity, target, and scan: those are not fields the
// client can set.
type CreateTicketInput struct {
	FindingID   uint
	Title       string
	Description string
	// Priority is optional; empty means "derive from the finding severity".
	Priority   entity.TicketPriority
	AssignedTo *uint
	// DueDate is optional; empty means "now + the SLA of the final priority".
	DueDate *time.Time
}

func (s *TicketService) CreateTicket(ctx context.Context, actor policy.Actor, in CreateTicketInput) (*entity.Ticket, error) {
	if !actor.Can(entity.PermTicketCreate) {
		return nil, apperr.ErrForbidden
	}
	title := strings.TrimSpace(in.Title)
	if title == "" || len(title) > maxTicketTitleLen {
		return nil, apperr.NewAppError("INVALID_INPUT", "Title must be 1-200 characters", 400)
	}
	if len(in.Description) > maxTicketDescriptionLen {
		return nil, apperr.NewAppError("INVALID_INPUT", "Description is too long", 400)
	}
	if in.Priority != "" && !isValidTicketPriority(in.Priority) {
		return nil, apperr.NewAppError("INVALID_INPUT", "Unknown priority", 400)
	}

	// A finding may only be turned into a ticket by somebody who can read the
	// scan it belongs to (prevents linking foreign findings).
	finding, err := s.findings.FindByID(ctx, in.FindingID)
	if err != nil {
		return nil, err
	}
	if _, err := s.ownedScan(ctx, actor, finding.ScanID); err != nil {
		return nil, apperr.ErrNotFound
	}

	if in.AssignedTo != nil {
		if err := s.checkAssignee(ctx, *in.AssignedTo); err != nil {
			return nil, err
		}
	}

	priority := in.Priority
	if priority == "" {
		priority = entity.PriorityFromSeverity(finding.Severity)
	}
	dueDate := in.DueDate
	if dueDate == nil {
		sla := ticketSLA[priority]
		if sla <= 0 {
			sla = ticketSLA[entity.TicketPriorityLow]
		}
		due := time.Now().UTC().Add(sla)
		dueDate = &due
	}

	ticket := &entity.Ticket{
		CreatedBy:   actor.ID,
		AssignedTo:  in.AssignedTo,
		ScanID:      finding.ScanID,
		FindingID:   finding.ID,
		Title:       title,
		Description: in.Description,
		Severity:    finding.Severity,
		Priority:    priority,
		Status:      entity.TicketStatusOpen,
		DueDate:     dueDate,
		UpdatedBy:   actor.ID,
	}
	if err := s.tickets.Create(ctx, ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

func (s *TicketService) GetTicket(ctx context.Context, actor policy.Actor, id uint) (*entity.Ticket, []*entity.TicketComment, error) {
	ticket, err := s.readableTicket(ctx, actor, id)
	if err != nil {
		return nil, nil, err
	}
	comments, err := s.tickets.ListComments(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return ticket, comments, nil
}

func (s *TicketService) ListTickets(ctx context.Context, actor policy.Actor, filter repository.TicketFilter) ([]*entity.Ticket, int64, error) {
	filter, err := s.scopeTicketFilter(actor, filter)
	if err != nil {
		return nil, 0, err
	}
	items, err := s.tickets.List(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.tickets.Count(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *TicketService) Stats(ctx context.Context, actor policy.Actor, filter repository.TicketFilter) (*entity.TicketStats, error) {
	filter, err := s.scopeTicketFilter(actor, filter)
	if err != nil {
		return nil, err
	}
	return s.tickets.Stats(ctx, filter)
}

func (s *TicketService) UpdateStatus(ctx context.Context, actor policy.Actor, id uint, status entity.TicketStatus) (*entity.Ticket, error) {
	if !actor.Can(entity.PermTicketUpdate) {
		return nil, apperr.ErrForbidden
	}
	if !entity.IsValidTicketStatus(status) {
		return nil, apperr.NewAppError("INVALID_INPUT", "Unknown ticket status", 400)
	}
	ticket, err := s.writableTicket(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if !entity.CanTransitionTicket(ticket.Status, status) {
		return nil, apperr.NewAppError("INVALID_INPUT",
			"Illegal status transition from "+string(ticket.Status)+" to "+string(status), 400)
	}

	ticket.Status = status
	ticket.UpdatedBy = actor.ID
	switch status {
	case entity.TicketStatusVerified, entity.TicketStatusWontFix:
		now := time.Now().UTC()
		ticket.ClosedAt = &now
	default:
		ticket.ClosedAt = nil
	}
	if err := s.tickets.Update(ctx, ticket); err != nil {
		return nil, err
	}
	return s.tickets.FindByID(ctx, id)
}

// Assign sets or clears the assignee. Nil unassigns; assigning requires that the
// target user exists and is active, otherwise the ticket would point at nobody.
func (s *TicketService) Assign(ctx context.Context, actor policy.Actor, id uint, userID *uint) (*entity.Ticket, error) {
	if !actor.Can(entity.PermTicketUpdate) {
		return nil, apperr.ErrForbidden
	}
	ticket, err := s.writableTicket(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if userID != nil {
		if err := s.checkAssignee(ctx, *userID); err != nil {
			return nil, err
		}
	}
	ticket.AssignedTo = userID
	ticket.UpdatedBy = actor.ID
	if err := s.tickets.Update(ctx, ticket); err != nil {
		return nil, err
	}
	return s.tickets.FindByID(ctx, id)
}

func (s *TicketService) AddComment(ctx context.Context, actor policy.Actor, id uint, message string) (*entity.TicketComment, error) {
	if _, err := s.readableTicket(ctx, actor, id); err != nil {
		return nil, err
	}
	message = strings.TrimSpace(message)
	if message == "" || len(message) > maxTicketCommentLen {
		return nil, apperr.NewAppError("INVALID_INPUT", "Message must be 1-2000 characters", 400)
	}
	comment := &entity.TicketComment{TicketID: id, AuthorID: actor.ID, Message: message}
	if err := s.tickets.CreateComment(ctx, comment); err != nil {
		return nil, err
	}
	return comment, nil
}

// ── authorisation helpers ───────────────────────────────────

// canReadAllTickets is the reviewer scope: an admin or an auditor needs the
// whole board to review remediation, everybody else sees their own work.
func canReadAllTickets(actor policy.Actor) bool {
	return actor.IsAdmin() || actor.Can(entity.PermAuditView)
}

func (s *TicketService) scopeTicketFilter(actor policy.Actor, filter repository.TicketFilter) (repository.TicketFilter, error) {
	if !actor.Can(entity.PermScanRead) && !actor.Can(entity.PermTicketCreate) && !actor.Can(entity.PermTicketUpdate) {
		return filter, apperr.ErrForbidden
	}
	if filter.Status != "" && !entity.IsValidTicketStatus(filter.Status) {
		return filter, apperr.NewAppError("INVALID_INPUT", "Unknown ticket status", 400)
	}
	if filter.Priority != "" && !isValidTicketPriority(filter.Priority) {
		return filter, apperr.NewAppError("INVALID_INPUT", "Unknown priority", 400)
	}
	if search := strings.TrimSpace(filter.Search); len(search) > maxTicketSearchLen {
		return filter, apperr.NewAppError("INVALID_INPUT", "Search term is too long", 400)
	}
	if !canReadAllTickets(actor) {
		filter.VisibleTo = actor.ID
		// Explicit owner filters must not widen the visible scope.
		filter.CreatedBy = 0
		if filter.AssignedTo != 0 && filter.AssignedTo != actor.ID {
			filter.AssignedTo = actor.ID
		}
	}
	return filter, nil
}

// readableTicket resolves a ticket the actor may see: reviewers see everything,
// everybody else only tickets they created or were assigned.
func (s *TicketService) readableTicket(ctx context.Context, actor policy.Actor, id uint) (*entity.Ticket, error) {
	if !actor.Can(entity.PermScanRead) && !actor.Can(entity.PermTicketCreate) && !actor.Can(entity.PermTicketUpdate) {
		return nil, apperr.ErrForbidden
	}
	if canReadAllTickets(actor) {
		return s.tickets.FindByID(ctx, id)
	}
	return s.tickets.FindByIDOwned(ctx, id, actor.ID)
}

// writableTicket is the narrow scope for state changes: the creator or the
// assignee, plus reviewers.
func (s *TicketService) writableTicket(ctx context.Context, actor policy.Actor, id uint) (*entity.Ticket, error) {
	if canReadAllTickets(actor) {
		return s.tickets.FindByID(ctx, id)
	}
	return s.tickets.FindByIDOwned(ctx, id, actor.ID)
}

func (s *TicketService) checkAssignee(ctx context.Context, userID uint) error {
	if s.users == nil {
		return nil
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			return apperr.NewAppError("INVALID_INPUT", "Assignee does not exist", 400)
		}
		return err
	}
	if !user.IsActive {
		return apperr.NewAppError("INVALID_INPUT", "Assignee is inactive", 400)
	}
	return nil
}

func (s *TicketService) ownedScan(ctx context.Context, actor policy.Actor, id uint) (*entity.ScanJob, error) {
	if canReadAllTickets(actor) {
		return s.scans.FindByID(ctx, id)
	}
	return s.scans.FindByIDOwned(ctx, id, actor.ID)
}

func isValidTicketPriority(p entity.TicketPriority) bool {
	switch p {
	case entity.TicketPriorityCritical, entity.TicketPriorityHigh,
		entity.TicketPriorityMedium, entity.TicketPriorityLow:
		return true
	default:
		return false
	}
}
