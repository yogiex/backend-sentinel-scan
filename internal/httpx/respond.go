// Package httpx centralises JSON responses and error envelopes so every
// endpoint speaks the same contract:
//
//	success: {"...": ...}
//	error:   {"error": {"code": "...", "message": "..."}}
//
// Every response is JSON with nosniff, which keeps browsers from sniffing
// user-controlled payloads as HTML (part of the stored-XSS defence).
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// MaxBodyBytes caps request bodies at 1 MiB.
const MaxBodyBytes int64 = 1 << 20

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

// JSON writes v as a JSON response.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		log.Printf("httpx: encode response: %v", err)
	}
}

// NoContent writes a 204 with no body.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// Error writes a structured error response.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

// ErrorFrom maps an application error to a safe HTTP response. Internal
// errors are logged but never leaked to the client.
func ErrorFrom(w http.ResponseWriter, err error) {
	var appErr *apperr.AppError
	if errors.As(err, &appErr) {
		Error(w, appErr.Status, appErr.Code, appErr.Message)
		return
	}
	log.Printf("httpx: unhandled error: %v", err)
	Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
}

// Decode reads a JSON body into dst with a hard size limit. It writes the
// error response itself and reports whether decoding succeeded.
func Decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			Error(w, http.StatusBadRequest, "INVALID_INPUT", "Request body is required")
			return false
		}
		Error(w, http.StatusBadRequest, "INVALID_INPUT", "Malformed JSON body")
		return false
	}
	return true
}
