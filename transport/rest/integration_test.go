package rest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/all2prosperity/auth_service/internal/testsupport"
	"github.com/all2prosperity/auth_service/transport/rest"

	"github.com/go-chi/chi/v5"
)

// testServer spins up the full REST stack over SQLite + miniredis.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	d := testsupport.NewCore(t)
	r := chi.NewRouter()
	rest.RegisterRoutes(r, d.Core, d.JWT)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

func doJSON(t *testing.T, srv *httptest.Server, method, path, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	var parsed map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}
	return resp, parsed
}

func registerAndLogin(t *testing.T, srv *httptest.Server, email string) map[string]any {
	t.Helper()
	resp, body := doJSON(t, srv, http.MethodPost, "/auth/register", "", map[string]string{
		"email": email, "password": "GoodPass1",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", resp.StatusCode)
	}
	return body
}

func tokensOf(t *testing.T, body map[string]any) (access, refresh string) {
	t.Helper()
	tk, ok := body["tokens"].(map[string]any)
	if !ok {
		t.Fatalf("response missing tokens: %v", body)
	}
	access, _ = tk["access_token"].(string)
	refresh, _ = tk["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens in %v", tk)
	}
	return access, refresh
}

func TestREST_RegisterShape(t *testing.T) {
	srv := testServer(t)
	body := registerAndLogin(t, srv, "shape@example.com")

	user, ok := body["user"].(map[string]any)
	if !ok {
		t.Fatalf("missing user object: %v", body)
	}
	if _, ok := user["user_id"].(string); !ok {
		t.Fatal("expected snake_case user_id")
	}
	if _, ok := user["created"].(string); !ok {
		t.Fatal("expected created timestamp string")
	}
	tokensOf(t, body) // asserts access_token/refresh_token present
}

func TestREST_LoginAndMe(t *testing.T) {
	srv := testServer(t)
	registerAndLogin(t, srv, "me@example.com")

	resp, body := doJSON(t, srv, http.MethodPost, "/auth/login", "", map[string]string{
		"email": "me@example.com", "password": "GoodPass1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	access, _ := tokensOf(t, body)

	resp, me := doJSON(t, srv, http.MethodGet, "/auth/me", access, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d, want 200", resp.StatusCode)
	}
	if _, ok := me["user_id"].(string); !ok {
		t.Fatalf("me missing user_id: %v", me)
	}
}

func TestREST_MeUnauthenticatedEnvelope(t *testing.T) {
	srv := testServer(t)
	resp, body := doJSON(t, srv, http.MethodGet, "/auth/me", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error envelope, got %v", body)
	}
	if errObj["code"] != "unauthenticated" {
		t.Fatalf("error code = %v, want unauthenticated", errObj["code"])
	}
}

func TestREST_LogoutRevokesToken(t *testing.T) {
	srv := testServer(t)
	body := registerAndLogin(t, srv, "logout@example.com")
	access, _ := tokensOf(t, body)

	// Valid before logout.
	if resp, _ := doJSON(t, srv, http.MethodGet, "/auth/me", access, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-logout me = %d, want 200", resp.StatusCode)
	}
	if resp, _ := doJSON(t, srv, http.MethodPost, "/auth/logout", access, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", resp.StatusCode)
	}
	// Rejected after logout (blacklist end-to-end).
	if resp, _ := doJSON(t, srv, http.MethodGet, "/auth/me", access, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-logout me = %d, want 401", resp.StatusCode)
	}
}

func TestREST_DuplicateRegisterConflict(t *testing.T) {
	srv := testServer(t)
	registerAndLogin(t, srv, "dup@example.com")
	resp, _ := doJSON(t, srv, http.MethodPost, "/auth/register", "", map[string]string{
		"email": "dup@example.com", "password": "GoodPass1",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate register = %d, want 409", resp.StatusCode)
	}
}

func TestREST_BruteForceTooManyRequests(t *testing.T) {
	srv := testServer(t)
	registerAndLogin(t, srv, "bf@example.com")

	// Security.LoginMaxAttempts = 3 → 4th attempt is locked out.
	for i := 0; i < 3; i++ {
		doJSON(t, srv, http.MethodPost, "/auth/login", "", map[string]string{
			"email": "bf@example.com", "password": "WrongPass1",
		})
	}
	resp, _ := doJSON(t, srv, http.MethodPost, "/auth/login", "", map[string]string{
		"email": "bf@example.com", "password": "GoodPass1",
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked login = %d, want 429", resp.StatusCode)
	}
}

func TestREST_RefreshToken(t *testing.T) {
	srv := testServer(t)
	body := registerAndLogin(t, srv, "rt@example.com")
	_, refresh := tokensOf(t, body)

	resp, out := doJSON(t, srv, http.MethodPost, "/auth/token/refresh", "", map[string]string{
		"refresh_token": refresh,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh = %d, want 200", resp.StatusCode)
	}
	if _, ok := out["access_token"].(string); !ok {
		t.Fatalf("refresh response missing access_token: %v", out)
	}
}

func TestREST_BadJSON(t *testing.T) {
	srv := testServer(t)

	// Malformed JSON.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/login", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed json = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Unknown field (DisallowUnknownFields).
	resp2, _ := doJSON(t, srv, http.MethodPost, "/auth/login", "", map[string]any{
		"email": "x@example.com", "password": "y", "bogus": true,
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", resp2.StatusCode)
	}
}
