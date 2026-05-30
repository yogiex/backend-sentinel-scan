package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// StreamHandler handles WebSocket connections for scan streaming.
func (h *Handler) StreamHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"error": "WebSocket not implemented"})
}

// ListAuthCredentials returns all credentials for the current user.
func (h *Handler) ListAuthCredentials(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	creds, err := h.authCredentialService.ListByUserID(r.Context(), 1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(creds)
}

// CreateAuthCredential creates a new credential in the vault.
func (h *Handler) CreateAuthCredential(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	var req struct {
		Name   string                 `json:"name"`
		Method string                 `json:"method"`
		Config map[string]interface{} `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	cred, err := h.authCredentialService.Create(r.Context(), 1, req.Name, "", req.Config, "", "", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cred)
}

// GetAuthCredential returns a specific credential by ID.
func (h *Handler) GetAuthCredential(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}
	cred, err := h.authCredentialService.GetByID(r.Context(), uint(id))
	if err != nil {
		http.Error(w, "Credential not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(cred)
}

// UpdateAuthCredential updates a credential.
func (h *Handler) UpdateAuthCredential(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	cred, err := h.authCredentialService.Update(r.Context(), uint(id), updates)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(cred)
}

// DeleteAuthCredential deletes a credential.
func (h *Handler) DeleteAuthCredential(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}
	if err := h.authCredentialService.Delete(r.Context(), uint(id)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// VerifyAuthCredential verifies a credential against its target.
func (h *Handler) VerifyAuthCredential(w http.ResponseWriter, r *http.Request) {
	if h.authCredentialService == nil {
		http.Error(w, "credential service not available", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}
	if h.sessionManager == nil {
		http.Error(w, "session manager not available", http.StatusInternalServerError)
		return
	}
	cred, err := h.authCredentialService.GetByID(r.Context(), uint(id))
	if err != nil {
		http.Error(w, "Credential not found", http.StatusNotFound)
		return
	}
	session, sessErr := h.sessionManager.StartSession(r.Context(), 0, cred)
	if sessErr != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(AuthCredentialVerifyResponse{
			Status: "failed", Message: "Authentication failed",
		})
		return
	}
	json.NewEncoder(w).Encode(AuthCredentialVerifyResponse{
		Status:  "verified",
		Message: "Successfully authenticated",
		Cookies: len(session.Cookies),
		Headers: len(session.Headers),
	})
}

// GetReportData returns aggregated scan report data.
func (h *Handler) GetReportData(w http.ResponseWriter, r *http.Request) {
	if h.reportService == nil {
		http.Error(w, "report service not available", http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	id, err := strconv.ParseUint(vars["id"], 10, 32)
	if err != nil {
		http.Error(w, "Invalid scan ID", http.StatusBadRequest)
		return
	}
	data, err := h.reportService.GetReportData(r.Context(), uint(id))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(data)
}

// ExportReport generates a PDF report.
func (h *Handler) ExportReport(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"status": "not_implemented"})
}

// DownloadReport downloads a generated PDF report.
func (h *Handler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{"status": "not_implemented"})
}
