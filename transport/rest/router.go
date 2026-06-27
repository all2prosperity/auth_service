// Package rest is the HTTP/JSON transport adapter for the auth use cases. It
// decodes JSON requests, calls core.AuthCore, and encodes JSON responses; it
// holds no business logic.
package rest

import (
	"net/http"

	"github.com/all2prosperity/auth_service/core"
	"github.com/all2prosperity/auth_service/services"

	"github.com/go-chi/chi/v5"
)

// Handler wires the auth core and JWT service to HTTP routes.
type Handler struct {
	core *core.AuthCore
	jwt  *services.JWTService
}

// RegisterRoutes mounts the auth REST API onto r under /auth.
func RegisterRoutes(r chi.Router, authCore *core.AuthCore, jwt *services.JWTService) {
	h := &Handler{core: authCore, jwt: jwt}

	r.Route("/auth", func(r chi.Router) {
		// Public endpoints.
		r.Post("/register", h.register)
		r.Post("/login", h.login)
		r.Post("/token/refresh", h.refresh)
		r.Post("/password-reset/start", h.startPasswordReset)
		r.Post("/password-reset/complete", h.completePasswordReset)
		r.Post("/code-login/start", h.startCodeLogin)
		r.Post("/code-login/complete", h.completeCodeLogin)
		r.Post("/code-register/start", h.startCodeRegister)
		r.Post("/code-register/complete", h.completeCodeRegister)

		// Protected endpoints.
		r.Group(func(r chi.Router) {
			r.Use(requireAuth(h.jwt))
			r.Post("/logout", h.logout)
			r.Get("/me", h.getMe)
		})
	})
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var body registerRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	res, err := h.core.Register(r.Context(), core.RegisterInput{
		Email:    body.Email,
		Phone:    body.Phone,
		Password: body.Password,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAuthResultResponse(res))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	res, err := h.core.Login(r.Context(), core.LoginInput{
		Email:    body.Email,
		Phone:    body.Phone,
		Password: body.Password,
		IP:       clientIP(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuthResultResponse(res))
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) {
	var body refreshRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	tokens, err := h.core.RefreshToken(r.Context(), core.RefreshInput{RefreshToken: body.RefreshToken})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toTokenPairResponse(*tokens))
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.core.Logout(r.Context()); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) getMe(w http.ResponseWriter, r *http.Request) {
	info, err := h.core.GetMe(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserInfoResponse(*info))
}

func (h *Handler) startPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body identifierRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	if err := h.core.StartPasswordReset(r.Context(), core.IdentifierInput{Email: body.Email, Phone: body.Phone}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) completePasswordReset(w http.ResponseWriter, r *http.Request) {
	var body completePasswordResetRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	if err := h.core.CompletePasswordReset(r.Context(), core.CompletePasswordResetInput{
		Token:       body.Token,
		NewPassword: body.NewPassword,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) startCodeLogin(w http.ResponseWriter, r *http.Request) {
	var body identifierRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	if err := h.core.StartCodeLogin(r.Context(), core.IdentifierInput{Email: body.Email, Phone: body.Phone}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) completeCodeLogin(w http.ResponseWriter, r *http.Request) {
	var body completeCodeLoginRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	res, err := h.core.CompleteCodeLogin(r.Context(), core.CompleteCodeLoginInput{
		Email: body.Email,
		Phone: body.Phone,
		Code:  body.Code,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuthResultResponse(res))
}

func (h *Handler) startCodeRegister(w http.ResponseWriter, r *http.Request) {
	var body startCodeRegisterRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	if err := h.core.StartCodeRegister(r.Context(), core.StartCodeRegisterInput{Phone: body.Phone}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func (h *Handler) completeCodeRegister(w http.ResponseWriter, r *http.Request) {
	var body completeCodeRegisterRequest
	if derr := decodeJSON(r, &body); derr != nil {
		writeError(w, derr)
		return
	}
	res, err := h.core.CompleteCodeRegister(r.Context(), core.CompleteCodeRegisterInput{
		Phone:    body.Phone,
		Code:     body.Code,
		Password: body.Password,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAuthResultResponse(res))
}
