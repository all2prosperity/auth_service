package rest

import (
	"time"

	"github.com/all2prosperity/auth_service/core"
)

// --- request bodies ---

type registerRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone_number,omitempty"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone_number,omitempty"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type identifierRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone_number,omitempty"`
}

type completePasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type completeCodeLoginRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone_number,omitempty"`
	Code  string `json:"code"`
}

type startCodeRegisterRequest struct {
	Phone string `json:"phone_number"`
}

type completeCodeRegisterRequest struct {
	Phone    string `json:"phone_number"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

// --- response bodies ---

type userInfoResponse struct {
	UserID  string   `json:"user_id"`
	Roles   []string `json:"roles"`
	Created string   `json:"created"`
}

type tokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type authResultResponse struct {
	User   userInfoResponse  `json:"user"`
	Tokens tokenPairResponse `json:"tokens"`
}

// --- mappers ---

func toUserInfoResponse(u core.UserInfo) userInfoResponse {
	return userInfoResponse{
		UserID:  u.UserID,
		Roles:   u.Roles,
		Created: u.Created.UTC().Format(time.RFC3339),
	}
}

func toTokenPairResponse(t core.TokenPair) tokenPairResponse {
	return tokenPairResponse{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}
}

func toAuthResultResponse(r *core.AuthResult) authResultResponse {
	return authResultResponse{
		User:   toUserInfoResponse(r.User),
		Tokens: toTokenPairResponse(r.Tokens),
	}
}
