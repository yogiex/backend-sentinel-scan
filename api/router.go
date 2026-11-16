package api

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
)

// RouterDeps are the transport-level dependencies of the router.
type RouterDeps struct {
	Auth             *middleware.Auth
	AllowedOrigins   []string
	AllowCredentials bool
}

// NewRouter wires the public and authenticated routes.
//
// Layering (outermost first): security headers, CORS, auth.
func NewRouter(h *Handler, deps RouterDeps) http.Handler {
	public := mux.NewRouter()
	public.HandleFunc("/health", h.HealthHandler).Methods(http.MethodGet)
	public.HandleFunc("/api/auth/login", h.LoginHandler).Methods(http.MethodPost)
	public.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotFound, "NOT_FOUND", "Route not found")
	})

	private := mux.NewRouter()
	private.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotFound, "NOT_FOUND", "Route not found")
	})
	private.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	})

	api := private.PathPrefix("/api").Subrouter()
	api.HandleFunc("/auth/me", h.MeHandler).Methods(http.MethodGet)

	api.HandleFunc("/scans", h.CreateScan).Methods(http.MethodPost)
	api.HandleFunc("/scans", h.ListScans).Methods(http.MethodGet)
	api.HandleFunc("/scans/{id}", h.GetScan).Methods(http.MethodGet)
	api.HandleFunc("/scans/{id}/results", h.GetScanResults).Methods(http.MethodGet)
	api.HandleFunc("/scans/{id}/cancel", h.CancelScan).Methods(http.MethodPost)
	api.HandleFunc("/scans/{id}/stream", h.StreamHandler).Methods(http.MethodGet)

	api.HandleFunc("/credentials", h.ListAuthCredentials).Methods(http.MethodGet)
	api.HandleFunc("/credentials", h.CreateAuthCredential).Methods(http.MethodPost)
	api.HandleFunc("/credentials/{id}", h.GetAuthCredential).Methods(http.MethodGet)
	api.HandleFunc("/credentials/{id}", h.UpdateAuthCredential).Methods(http.MethodPut)
	api.HandleFunc("/credentials/{id}", h.DeleteAuthCredential).Methods(http.MethodDelete)
	api.HandleFunc("/credentials/{id}/verify", h.VerifyAuthCredential).Methods(http.MethodPost)

	api.HandleFunc("/scans/{id}/report-data", h.GetReportData).Methods(http.MethodGet)
	api.HandleFunc("/scans/{id}/report/export", h.ExportReport).Methods(http.MethodPost)
	api.HandleFunc("/scans/{id}/report/download", h.DownloadReport).Methods(http.MethodGet)

	api.HandleFunc("/templates", h.ListTemplates).Methods(http.MethodGet)
	api.HandleFunc("/templates/{id}", h.GetTemplate).Methods(http.MethodGet)

	var protected http.Handler = private
	if deps.Auth != nil {
		protected = deps.Auth.Require(private)
	}

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/api/auth/login" {
			public.ServeHTTP(w, r)
			return
		}
		if deps.Auth == nil {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication is not configured")
			return
		}
		protected.ServeHTTP(w, r)
	})

	return middleware.Chain(dispatch,
		middleware.SecurityHeaders,
		middleware.CORS(deps.AllowedOrigins, deps.AllowCredentials),
	)
}
