package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/all2prosperity/auth_service/config"
	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/services"
)

func TestCodeToStatus(t *testing.T) {
	cases := map[core.Code]int{
		core.CodeInvalidArgument:   http.StatusBadRequest,
		core.CodeUnauthenticated:   http.StatusUnauthorized,
		core.CodePermissionDenied:  http.StatusForbidden,
		core.CodeNotFound:          http.StatusNotFound,
		core.CodeAlreadyExists:     http.StatusConflict,
		core.CodeResourceExhausted: http.StatusTooManyRequests,
		core.CodeInternal:          http.StatusInternalServerError,
	}
	for code, want := range cases {
		if got := codeToStatus(code); got != want {
			t.Errorf("codeToStatus(%v) = %d, want %d", code, got, want)
		}
	}
}

func TestRequireAuth_RejectsMissingToken(t *testing.T) {
	jwt := services.NewJWTService(&config.JWTConfig{AccessSecret: "test-secret"})
	mw := requireAuth(jwt)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be reached without a valid token")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var env errorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("response is not a JSON error envelope: %v", err)
	}
	if env.Error.Code != "unauthenticated" {
		t.Errorf("error code = %q, want unauthenticated", env.Error.Code)
	}
}

func TestDecodeJSON_RejectsUnknownField(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"bogus":1}`))
	var body loginRequest
	if derr := decodeJSON(req, &body); derr == nil || derr.Code != core.CodeInvalidArgument {
		t.Fatalf("expected invalid_argument error for unknown field, got %v", derr)
	}
}

func TestBearerToken(t *testing.T) {
	if got := bearerToken("Bearer abc.def"); got != "abc.def" {
		t.Errorf("bearerToken = %q, want abc.def", got)
	}
	if got := bearerToken("Basic xyz"); got != "" {
		t.Errorf("bearerToken(non-bearer) = %q, want empty", got)
	}
}
