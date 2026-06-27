package rest

import (
	"encoding/json"
	"net/http"

	"github.com/all2prosperity/auth_service/core"
)

// errorEnvelope is the JSON error response body: {"error": {"code","message"}}.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// codeToStatus maps a transport-agnostic core.Code to an HTTP status.
func codeToStatus(code core.Code) int {
	switch code {
	case core.CodeInvalidArgument:
		return http.StatusBadRequest
	case core.CodeUnauthenticated:
		return http.StatusUnauthorized
	case core.CodePermissionDenied:
		return http.StatusForbidden
	case core.CodeNotFound:
		return http.StatusNotFound
	case core.CodeAlreadyExists:
		return http.StatusConflict
	case core.CodeResourceExhausted:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// codeToString gives the stable machine-readable string for a core.Code.
func codeToString(code core.Code) string {
	switch code {
	case core.CodeInvalidArgument:
		return "invalid_argument"
	case core.CodeUnauthenticated:
		return "unauthenticated"
	case core.CodePermissionDenied:
		return "permission_denied"
	case core.CodeNotFound:
		return "not_found"
	case core.CodeAlreadyExists:
		return "already_exists"
	case core.CodeResourceExhausted:
		return "resource_exhausted"
	default:
		return "internal"
	}
}

// writeJSON writes v as a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// writeError translates a core.Error into an HTTP status + JSON envelope.
func writeError(w http.ResponseWriter, err *core.Error) {
	if err == nil {
		writeError(w, &core.Error{Code: core.CodeInternal, Message: "unknown error"})
		return
	}
	writeJSON(w, codeToStatus(err.Code), errorEnvelope{
		Error: errorBody{Code: codeToString(err.Code), Message: err.Message},
	})
}

// decodeJSON parses the request body into dst, returning a core.Error on failure.
func decodeJSON(r *http.Request, dst any) *core.Error {
	if r.Body == nil {
		return &core.Error{Code: core.CodeInvalidArgument, Message: "request body is required"}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return &core.Error{Code: core.CodeInvalidArgument, Message: "invalid request body: " + err.Error()}
	}
	return nil
}
