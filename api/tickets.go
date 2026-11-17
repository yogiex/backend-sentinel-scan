package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
)

// ticketListResponse mirrors scanListResponse so a client can paginate every
// collection the same way.
type ticketListResponse struct {
	Items    []*entity.Ticket `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// ticketDetailResponse is the ticket with its comments flattened in, which is
// what a detail view needs and avoids a second round trip.
type ticketDetailResponse struct {
	*entity.Ticket
	Comments []*entity.TicketComment `json:"comments"`
}

type createTicketRequest struct {
	FindingID   uint       `json:"finding_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Priority    string     `json:"priority"`
	AssignedTo  *uint      `json:"assigned_to"`
	DueDate     *time.Time `json:"due_date"`
}

type updateTicketStatusRequest struct {
	Status string `json:"status"`
}

type assignTicketRequest struct {
	AssignedTo *uint `json:"assigned_to"`
}

type createTicketCommentRequest struct {
	Message string `json:"message"`
}

// ListTickets serves GET /api/tickets.
func (h *Handler) ListTickets(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	filter := repository.TicketFilter{
		Status:     entity.TicketStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Priority:   entity.TicketPriority(strings.TrimSpace(r.URL.Query().Get("priority"))),
		Severity:   strings.TrimSpace(r.URL.Query().Get("severity")),
		ScanID:     queryUint(r, "scan_id"),
		AssignedTo: queryUint(r, "assigned_to"),
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		Page:       page,
		PageSize:   pageSize,
	}
	items, total, err := h.tickets.ListTickets(r.Context(), a, filter)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ticketListResponse{Items: items, Total: total, Page: page, PageSize: pageSize})
}

// ListOverdueTickets serves GET /api/tickets/overdue.
func (h *Handler) ListOverdueTickets(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	filter := repository.TicketFilter{
		OverdueOnly: true,
		Page:        page,
		PageSize:    pageSize,
	}
	items, total, err := h.tickets.ListTickets(r.Context(), a, filter)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ticketListResponse{Items: items, Total: total, Page: page, PageSize: pageSize})
}

// TicketStatsHandler serves GET /api/tickets/stats.
func (h *Handler) TicketStatsHandler(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	filter := repository.TicketFilter{
		AssignedTo: queryUint(r, "assigned_to"),
		ScanID:     queryUint(r, "scan_id"),
	}
	stats, err := h.tickets.Stats(r.Context(), a, filter)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, stats)
}

// CreateTicket serves POST /api/tickets.
func (h *Handler) CreateTicket(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	var req createTicketRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	ticket, err := h.tickets.CreateTicket(r.Context(), a, application.CreateTicketInput{
		FindingID:   req.FindingID,
		Title:       req.Title,
		Description: req.Description,
		Priority:    entity.TicketPriority(strings.TrimSpace(req.Priority)),
		AssignedTo:  req.AssignedTo,
		DueDate:     req.DueDate,
	})
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, ticket)
}

// GetTicket serves GET /api/tickets/{id}.
func (h *Handler) GetTicket(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid ticket ID")
		return
	}
	ticket, comments, err := h.tickets.GetTicket(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ticketDetailResponse{Ticket: ticket, Comments: comments})
}

// UpdateTicketStatus serves PATCH /api/tickets/{id}/status.
func (h *Handler) UpdateTicketStatus(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid ticket ID")
		return
	}
	var req updateTicketStatusRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	ticket, err := h.tickets.UpdateStatus(r.Context(), a, id, entity.TicketStatus(strings.TrimSpace(req.Status)))
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ticket)
}

// AssignTicket serves POST /api/tickets/{id}/assign. A null assignee unassigns.
func (h *Handler) AssignTicket(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid ticket ID")
		return
	}
	var req assignTicketRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	ticket, err := h.tickets.Assign(r.Context(), a, id, req.AssignedTo)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, ticket)
}

// AddTicketComment serves POST /api/tickets/{id}/comments.
func (h *Handler) AddTicketComment(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid ticket ID")
		return
	}
	var req createTicketCommentRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	comment, err := h.tickets.AddComment(r.Context(), a, id, req.Message)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, comment)
}

// queryUint reads an optional unsigned query parameter, returning zero when it
// is absent or malformed. Zero means "no filter", which is why a malformed value
// must not become a 500.
func queryUint(r *http.Request, name string) uint {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0
	}
	return uint(v)
}
