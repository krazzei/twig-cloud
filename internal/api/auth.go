package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/twig/twig-cloud/internal/auth"
)

// Boundary validation limits.
const (
	minPasswordChars = 8
	// maxPasswordBytes bounds the work an argon2 call does on attacker input.
	maxPasswordBytes   = 1024
	maxEmailBytes      = 254 // RFC 5321 path limit
	maxDeviceNameChars = 100
)

type credentialsRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"` // seconds
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"` // seconds
}

type sessionResponse struct {
	User auth.User `json:"user"`
	tokenResponse
}

func newTokenResponse(t auth.Tokens) tokenResponse {
	return tokenResponse{
		TokenType:        "Bearer",
		AccessToken:      t.AccessToken,
		ExpiresIn:        int64(t.AccessExpiresAt.Sub(t.IssuedAt) / time.Second),
		RefreshToken:     t.RefreshToken,
		RefreshExpiresIn: int64(t.RefreshExpiresAt.Sub(t.IssuedAt) / time.Second),
	}
}

// POST /auth/register {email, password, device_name} -> 201 session
func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	email, err := normalizeEmail(req.Email)
	if err == nil {
		err = validateNewPassword(req.Password)
	}
	var device string
	if err == nil {
		device, err = normalizeDeviceName(req.DeviceName)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}

	user, tokens, err := a.auth.Register(r.Context(), email, req.Password, device)
	switch {
	case errors.Is(err, auth.ErrEmailTaken):
		writeError(w, http.StatusConflict, codeEmailTaken, "email is already registered")
	case err != nil:
		a.writeInternal(w, r, err)
	default:
		writeJSON(w, http.StatusCreated, sessionResponse{User: user, tokenResponse: newTokenResponse(tokens)})
	}
}

// POST /auth/login {email, password, device_name} -> 200 session
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	email, err := normalizeEmail(req.Email)
	if err == nil && (req.Password == "" || len(req.Password) > maxPasswordBytes) {
		// No minimum-length check here: that's a registration rule, and a
		// short password simply won't match.
		err = fmt.Errorf("password must be 1-%d bytes", maxPasswordBytes)
	}
	var device string
	if err == nil {
		device, err = normalizeDeviceName(req.DeviceName)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}

	user, tokens, err := a.auth.Login(r.Context(), email, req.Password, device)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "invalid email or password")
	case err != nil:
		a.writeInternal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, sessionResponse{User: user, tokenResponse: newTokenResponse(tokens)})
	}
}

// POST /auth/refresh {refresh_token} -> 200 tokens
//
// The presented refresh token is consumed; the response carries its
// replacement. Re-presenting a consumed token re-issues a fresh pair while
// it is within the retry grace window (a refresh whose response was lost
// over a flaky network), and revokes the session once that window has
// passed (the token was copied).
func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.RefreshToken)
	if token == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "refresh_token is required")
		return
	}

	tokens, err := a.auth.Refresh(r.Context(), token)
	switch {
	case errors.Is(err, auth.ErrTokenReused):
		writeError(w, http.StatusUnauthorized, codeTokenReused,
			"refresh token was already used; this session has been revoked, log in again")
	case errors.Is(err, auth.ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, codeInvalidToken, "invalid or expired refresh token")
	case err != nil:
		a.writeInternal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, newTokenResponse(tokens))
	}
}

// POST /auth/logout (bearer) -> 204
//
// Revokes the session the bearer token belongs to, so the client doesn't
// need to send its refresh token. Other logins, even on the same device
// name, keep working.
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if err := a.auth.Logout(r.Context(), sess); err != nil {
		a.writeInternal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /auth/me (bearer) -> 200 user
func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	userID, _ := UserID(r.Context())
	user, err := a.auth.User(r.Context(), userID)
	switch {
	case errors.Is(err, auth.ErrUserNotFound):
		writeError(w, http.StatusUnauthorized, codeInvalidToken, "user no longer exists")
	case err != nil:
		a.writeInternal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, user)
	}
}

// normalizeEmail trims and lowercases s and checks it is a bare address
// (local@domain, no display name or angle brackets).
func normalizeEmail(s string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(s))
	if email == "" {
		return "", errors.New("email is required")
	}
	if len(email) > maxEmailBytes {
		return "", fmt.Errorf("email must be at most %d bytes", maxEmailBytes)
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", errors.New("email is not a valid address")
	}
	return email, nil
}

// validateNewPassword enforces the registration password policy. Passwords
// are never trimmed or otherwise altered.
func validateNewPassword(p string) error {
	if utf8.RuneCountInString(p) < minPasswordChars {
		return fmt.Errorf("password must be at least %d characters", minPasswordChars)
	}
	if len(p) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	return nil
}

// normalizeDeviceName trims s and requires a non-empty, bounded name. The
// name is informational; session identity comes from the session_id
// assigned at login.
func normalizeDeviceName(s string) (string, error) {
	name := strings.TrimSpace(s)
	if name == "" {
		return "", errors.New("device_name is required")
	}
	if utf8.RuneCountInString(name) > maxDeviceNameChars || !utf8.ValidString(name) {
		return "", fmt.Errorf("device_name must be valid UTF-8, at most %d characters", maxDeviceNameChars)
	}
	return name, nil
}
