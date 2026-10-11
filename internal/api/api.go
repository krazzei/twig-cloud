// Package api is the HTTP layer: routing, request validation, JSON
// encoding, and middleware. Business logic lives in the domain packages
// (auth, and later upload/tree); handlers here translate between HTTP and
// those packages.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/twig/twig-cloud/internal/auth"
)

// maxJSONBodyBytes caps JSON request bodies. Auth payloads are tiny.
const maxJSONBodyBytes = 64 << 10

// API holds the dependencies shared by all handlers.
type API struct {
	auth   *auth.Service
	logger *slog.Logger
}

// NewHandler returns the root handler with every route registered.
func NewHandler(authSvc *auth.Service, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	a := &API{auth: authSvc, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealthz)

	mux.HandleFunc("POST /auth/register", a.handleRegister)
	mux.HandleFunc("POST /auth/login", a.handleLogin)
	mux.HandleFunc("POST /auth/refresh", a.handleRefresh)
	mux.Handle("POST /auth/logout", a.requireAuth(http.HandlerFunc(a.handleLogout)))
	mux.Handle("GET /auth/me", a.requireAuth(http.HandlerFunc(a.handleMe)))

	return mux
}

func (a *API) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Error codes returned in the "error" field of JSON error bodies.
const (
	codeInvalidRequest     = "invalid_request"
	codeInvalidCredentials = "invalid_credentials"
	codeEmailTaken         = "email_taken"
	codeInvalidToken       = "invalid_token"
	codeTokenReused        = "token_reused"
	codeInternal           = "internal_error"
)

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		// RFC 6750 §3: tell clients which scheme to use.
		w.Header().Set("WWW-Authenticate", `Bearer realm="twig-cloud"`)
	}
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

// writeInternal logs err and returns a generic 500 so internals never leak
// to clients.
func (a *API) writeInternal(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.ErrorContext(r.Context(), "request failed",
		"method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, codeInternal, "internal server error")
}

// decodeJSON reads a single JSON object from r's body into dst. On failure
// it writes a 400 and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		msg := "request body must be a JSON object"
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			msg = "request body too large"
		}
		writeError(w, http.StatusBadRequest, codeInvalidRequest, msg)
		return false
	}
	return true
}
