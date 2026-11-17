package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
)

const (
	// streamWriteTimeout bounds every frame write so a stalled client cannot
	// pin a goroutine forever.
	streamWriteTimeout = 10 * time.Second
	// streamPingInterval keeps idle connections alive through proxies and
	// detects half-open connections.
	streamPingInterval = 25 * time.Second
	// streamStatusPoll re-reads the persisted scan row. The bus drops events for
	// subscribers that cannot keep up, so the terminal event must have a second
	// source of truth.
	streamStatusPoll = 2 * time.Second
	// streamSnapshotFindings bounds the catch-up burst sent to a late subscriber.
	streamSnapshotFindings = 50
)

// streamEnvelope is the wire format of every frame: {"type": "...", "data": {}}.
type streamEnvelope struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// StreamHandler upgrades the request to a WebSocket and forwards scan events.
//
// Authentication is the normal bearer middleware; for browsers, which cannot
// set headers on a WebSocket handshake, middleware.QueryToken also accepts the
// token in the query string for this route only.
func (h *Handler) StreamHandler(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid scan ID")
		return
	}
	// Ownership is checked before the upgrade: a socket to a foreign scan would
	// otherwise leak findings in real time.
	scan, err := h.scans.GetScan(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	if !h.originAllowed(r.Header.Get("Origin")) {
		httpx.Error(w, http.StatusForbidden, "FORBIDDEN", "Origin is not allowed")
		return
	}
	if h.events == nil {
		// Same rule as everywhere else in this codebase: a feature that is not
		// wired says so instead of pretending to stream.
		httpx.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Event streaming is not configured")
		return
	}

	upgrader := websocket.Upgrader{
		HandshakeTimeout: 5 * time.Second,
		// Origin was validated above against the exact-match allowlist.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote an HTTP error response.
		return
	}
	defer conn.Close()

	// A hijacked connection does not cancel the request context when the client
	// vanishes, so a reader is the only reliable disconnect signal.
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Subscribe before the snapshot is written: otherwise an event published
	// while the snapshot frames are still being sent lands in the gap between
	// "read the state" and "listen for changes" and is never delivered.
	events := h.events.Subscribe(fmt.Sprint(id))
	defer h.events.Unsubscribe(fmt.Sprint(id), events)

	// Catch-up snapshot: a client that connects mid-scan still learns the
	// current counters and the findings recorded so far.
	if scan.Progress != nil {
		if !writeEnvelope(conn, streamEnvelope{Type: "progress", Data: progressPayload(scan.ID, *scan.Progress)}) {
			return
		}
	}
	if findings, err := h.scans.GetResults(r.Context(), a, id, streamSnapshotFindings); err == nil {
		for _, f := range findings {
			if !writeEnvelope(conn, streamEnvelope{Type: "finding", Data: findingPayload(f)}) {
				return
			}
		}
	}
	if isTerminalStatus(scan.Status) {
		writeEnvelope(conn, terminalEnvelope(scan))
		return
	}

	ping := time.NewTicker(streamPingInterval)
	defer ping.Stop()
	poll := time.NewTicker(streamStatusPoll)
	defer poll.Stop()

	for {
		select {
		case <-clientGone:
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !writeEnvelope(conn, streamEnvelope{Type: string(ev.Type), Data: ev.Payload}) {
				return
			}
			if ev.Type == event.EventTypeComplete || ev.Type == event.EventTypeFailed {
				return
			}
		case <-ping.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(streamWriteTimeout)); err != nil {
				return
			}
		case <-poll.C:
			current, err := h.scans.GetScan(r.Context(), a, id)
			if err != nil {
				return
			}
			if isTerminalStatus(current.Status) {
				writeEnvelope(conn, terminalEnvelope(current))
				return
			}
		}
	}
}

func writeEnvelope(conn *websocket.Conn, envelope streamEnvelope) bool {
	payload, err := json.Marshal(envelope)
	if err != nil {
		return false
	}
	if err := conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
		return false
	}
	return conn.WriteMessage(websocket.TextMessage, payload) == nil
}

func progressPayload(scanID uint, progress entity.ScanProgress) map[string]any {
	return map[string]any{
		"scan_id":     scanID,
		"completed":   progress.Completed,
		"failed":      progress.Failed,
		"total":       progress.TotalTasks,
		"in_progress": progress.InProgress,
		"phase":       progress.Phase,
	}
}

func findingPayload(f *entity.Finding) map[string]any {
	return map[string]any{
		"id":          f.ID,
		"scan_id":     f.ScanID,
		"target":      f.Target,
		"template_id": f.TemplateID,
		"severity":    f.Severity,
		"details":     f.Details,
	}
}

func terminalEnvelope(scan *entity.ScanJob) streamEnvelope {
	if scan.Status == entity.ScanStatusFailed || scan.Status == entity.ScanStatusCancelled {
		return streamEnvelope{Type: string(event.EventTypeFailed), Data: map[string]any{
			"scan_id": scan.ID,
			"status":  scan.Status,
			"reason":  string(scan.Status),
		}}
	}
	return streamEnvelope{Type: string(event.EventTypeComplete), Data: map[string]any{
		"scan_id":   scan.ID,
		"truncated": scan.Truncated,
	}}
}

func isTerminalStatus(status entity.ScanStatus) bool {
	return status == entity.ScanStatusCompleted ||
		status == entity.ScanStatusFailed ||
		status == entity.ScanStatusCancelled
}

// originAllowed enforces the same exact-match rule as the CORS middleware. A
// missing Origin header is allowed: that is a non-browser client, which still
// has to present a token.
func (h *Handler) originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	_, ok := h.allowedOrigins[origin]
	return ok
}
