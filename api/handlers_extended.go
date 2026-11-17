package api

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
)

// ── Credentials ─────────────────────────────────────────────

type createCredentialRequest struct {
	Name          string         `json:"name"`
	Method        string         `json:"method"`
	Config        map[string]any `json:"config"`
	LoginURL      string         `json:"login_url"`
	VerifyURL     string         `json:"verify_url"`
	VerifyPattern string         `json:"verify_pattern"`
}

func (h *Handler) ListAuthCredentials(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	creds, err := h.creds.List(r.Context(), a)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	for _, c := range creds {
		h.creds.Sanitize(c)
	}
	httpx.JSON(w, http.StatusOK, creds)
}

func (h *Handler) CreateAuthCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	var req createCredentialRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	cred, err := h.creds.Create(r.Context(), a, req.Name, entity.AuthMethod(req.Method),
		req.Config, req.LoginURL, req.VerifyURL, req.VerifyPattern)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	h.creds.Sanitize(cred)
	httpx.JSON(w, http.StatusCreated, cred)
}

func (h *Handler) GetAuthCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid credential ID")
		return
	}
	cred, err := h.creds.GetByID(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	h.creds.Sanitize(cred)
	httpx.JSON(w, http.StatusOK, cred)
}

func (h *Handler) UpdateAuthCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid credential ID")
		return
	}
	var updates map[string]any
	if !httpx.Decode(w, r, &updates) {
		return
	}
	cred, err := h.creds.Update(r.Context(), a, id, updates)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	h.creds.Sanitize(cred)
	httpx.JSON(w, http.StatusOK, cred)
}

func (h *Handler) DeleteAuthCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid credential ID")
		return
	}
	if err := h.creds.Delete(r.Context(), a, id); err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.NoContent(w)
}

type verifyResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Cookies int    `json:"cookies"`
	Headers int    `json:"headers"`
}

// VerifyAuthCredential checks the configured verify URL through the SSRF-safe
// client. It never follows the credential's login flow implicitly.
func (h *Handler) VerifyAuthCredential(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid credential ID")
		return
	}
	cred, err := h.creds.GetByID(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	if strings.TrimSpace(cred.VerifyURL) == "" {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Credential has no verify_url")
		return
	}
	if h.guard == nil {
		httpx.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Verification is not configured")
		return
	}
	if _, err := h.guard.Validate(r.Context(), cred.VerifyURL); err != nil {
		httpx.Error(w, http.StatusBadRequest, "INVALID_TARGET", "verify_url rejected: "+err.Error())
		return
	}

	client := h.guard.Client(15*time.Second, 3)
	resp, err := client.Get(cred.VerifyURL) // #nosec G107 -- URL validated above and re-checked at dial time
	if err != nil {
		httpx.JSON(w, http.StatusOK, verifyResponse{Status: "failed", Message: "request failed"})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	matched := cred.VerifyPattern == "" || strings.Contains(string(body), cred.VerifyPattern)
	if !matched {
		httpx.JSON(w, http.StatusOK, verifyResponse{Status: "failed", Message: "verify pattern not found"})
		return
	}
	if err := h.creds.UpdateLastVerified(r.Context(), a, id); err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, verifyResponse{Status: "verified", Message: "verify pattern matched"})
}

// ── Reports ─────────────────────────────────────────────────

func (h *Handler) GetReportData(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid scan ID")
		return
	}
	data, err := h.reports.GetReportData(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, data)
}

func (h *Handler) ExportReport(w http.ResponseWriter, r *http.Request) {
	httpx.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Report export is not implemented yet")
}

func (h *Handler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	httpx.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Report download is not implemented yet")
}
