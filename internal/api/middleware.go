package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/twig/twig-cloud/internal/auth"
)

type sessionKey struct{}

// UserID returns the authenticated user's id. It is only set on requests
// that passed requireAuth.
func UserID(ctx context.Context) (string, bool) {
	sess, ok := ctx.Value(sessionKey{}).(auth.Session)
	return sess.UserID, ok
}

func sessionFrom(ctx context.Context) (auth.Session, bool) {
	sess, ok := ctx.Value(sessionKey{}).(auth.Session)
	return sess, ok
}

// requireAuth resolves "Authorization: Bearer <access_token>" to a session
// stored in the request context. Missing, malformed, unknown, expired, or
// revoked tokens get a 401 JSON body.
func (a *API) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, codeInvalidToken, "missing or malformed bearer token")
			return
		}
		sess, err := a.auth.Authenticate(r.Context(), token)
		if errors.Is(err, auth.ErrInvalidToken) {
			writeError(w, http.StatusUnauthorized, codeInvalidToken, "invalid or expired access token")
			return
		}
		if err != nil {
			a.writeInternal(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
