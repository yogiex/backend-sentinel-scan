package errors

import "net/http"

type AppError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (e *AppError) Error() string { return e.Message }

func NewAppError(code, message string, status int) *AppError {
	return &AppError{Code: code, Message: message, Status: status}
}

var (
	ErrNotFound       = &AppError{Code: "NOT_FOUND", Message: "Resource not found", Status: http.StatusNotFound}
	ErrUnauthorized   = &AppError{Code: "UNAUTHORIZED", Message: "Unauthorized", Status: http.StatusUnauthorized}
	ErrForbidden      = &AppError{Code: "FORBIDDEN", Message: "Insufficient permissions", Status: http.StatusForbidden}
	ErrInvalidInput   = &AppError{Code: "INVALID_INPUT", Message: "Invalid request body", Status: http.StatusBadRequest}
	ErrConflict       = &AppError{Code: "CONFLICT", Message: "Resource conflict", Status: http.StatusConflict}
	ErrInternalServer = &AppError{Code: "INTERNAL_ERROR", Message: "Internal server error", Status: http.StatusInternalServerError}
)
