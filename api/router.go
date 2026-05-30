package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/event"
)

func NewRouter(h *Handler, eventBus *event.Bus) http.Handler {
	r := mux.NewRouter()

	// Health
	r.HandleFunc("/health", h.HealthHandler).Methods("GET")

	// Scans
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/scans", h.CreateScan).Methods("POST")
	api.HandleFunc("/scans/{id}", h.GetScan).Methods("GET")
	api.HandleFunc("/scans/{id}/results", h.GetScanResults).Methods("GET")

	// WebSocket stream
	api.HandleFunc("/scans/{id}/stream", h.StreamHandler).Methods("GET")

	// Credentials
	api.HandleFunc("/credentials", h.ListAuthCredentials).Methods("GET")
	api.HandleFunc("/credentials", h.CreateAuthCredential).Methods("POST")
	api.HandleFunc("/credentials/{id}", h.GetAuthCredential).Methods("GET")
	api.HandleFunc("/credentials/{id}", h.UpdateAuthCredential).Methods("PUT")
	api.HandleFunc("/credentials/{id}", h.DeleteAuthCredential).Methods("DELETE")
	api.HandleFunc("/credentials/{id}/verify", h.VerifyAuthCredential).Methods("POST")

	// Reports
	api.HandleFunc("/scans/{id}/report-data", h.GetReportData).Methods("GET")
	api.HandleFunc("/scans/{id}/report/export", h.ExportReport).Methods("POST")
	api.HandleFunc("/scans/{id}/report/download", h.DownloadReport).Methods("GET")

	// Templates
	api.HandleFunc("/templates", h.ListTemplates).Methods("GET")
	api.HandleFunc("/templates/{id}", h.GetTemplate).Methods("GET")

	return r
}
