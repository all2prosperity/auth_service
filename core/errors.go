package core

import "fmt"

// Code is a transport-agnostic error category. Adapters map it to their own
// status space (HTTP status, gRPC/Connect code, ...).
type Code int

const (
	CodeInternal Code = iota
	CodeInvalidArgument
	CodeUnauthenticated
	CodePermissionDenied
	CodeNotFound
	CodeAlreadyExists
	CodeResourceExhausted
)

// Error is a domain error carrying a transport-agnostic Code.
type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string { return e.Message }

// newError builds a domain Error with a formatted message.
func newError(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Convenience constructors mirroring the categories above.
func errInternal(format string, args ...any) *Error {
	return newError(CodeInternal, format, args...)
}
func errInvalidArgument(format string, args ...any) *Error {
	return newError(CodeInvalidArgument, format, args...)
}
func errUnauthenticated(format string, args ...any) *Error {
	return newError(CodeUnauthenticated, format, args...)
}
func errPermissionDenied(format string, args ...any) *Error {
	return newError(CodePermissionDenied, format, args...)
}
func errNotFound(format string, args ...any) *Error {
	return newError(CodeNotFound, format, args...)
}
func errAlreadyExists(format string, args ...any) *Error {
	return newError(CodeAlreadyExists, format, args...)
}
func errResourceExhausted(format string, args ...any) *Error {
	return newError(CodeResourceExhausted, format, args...)
}
