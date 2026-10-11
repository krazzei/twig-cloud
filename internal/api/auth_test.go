package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twig/twig-cloud/internal/auth"
	"github.com/twig/twig-cloud/internal/config"
	"github.com/twig/twig-cloud/internal/database"
)

// fakeClock is a manually advanced clock shared by the auth service.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testEnv struct {
	t     *testing.T
	srv   *httptest.Server
	db    *database.DB
	clock *fakeClock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "twig.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	clock := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc, err := auth.NewService(db, auth.Options{
		AccessTTL:  config.DefaultAccessTokenTTL,
		RefreshTTL: config.DefaultRefreshTokenTTL,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	srv := httptest.NewServer(NewHandler(svc, nil))
	t.Cleanup(srv.Close)
	return &testEnv{t: t, srv: srv, db: db, clock: clock}
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r response) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

func (r response) errorCode(t *testing.T) string {
	t.Helper()
	var e errorBody
	r.decode(t, &e)
	if e.Message == "" {
		t.Errorf("error body %q has no message", r.body)
	}
	return e.Error
}

func (e *testEnv) do(method, path, bearer string, body any) response {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			e.t.Fatalf("marshal: %v", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: data}
}

func (e *testEnv) register(email, password, device string) sessionResponse {
	e.t.Helper()
	r := e.do("POST", "/auth/register", "", credentialsRequest{email, password, device})
	if r.status != http.StatusCreated {
		e.t.Fatalf("register status = %d, body %s", r.status, r.body)
	}
	var s sessionResponse
	r.decode(e.t, &s)
	return s
}

func (e *testEnv) login(email, password, device string) sessionResponse {
	e.t.Helper()
	r := e.do("POST", "/auth/login", "", credentialsRequest{email, password, device})
	if r.status != http.StatusOK {
		e.t.Fatalf("login status = %d, body %s", r.status, r.body)
	}
	var s sessionResponse
	r.decode(e.t, &s)
	return s
}

func (e *testEnv) refresh(token string) response {
	e.t.Helper()
	return e.do("POST", "/auth/refresh", "", refreshRequest{RefreshToken: token})
}

// expectStatus asserts the status and, for 401s, the JSON error code and the
// WWW-Authenticate challenge.
func expectStatus(t *testing.T, r response, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d; body %s", r.status, status, r.body)
	}
	if code == "" {
		return
	}
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if got := r.errorCode(t); got != code {
		t.Errorf("error code = %q, want %q", got, code)
	}
	if status == http.StatusUnauthorized && !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("401 without Bearer WWW-Authenticate header")
	}
}

func (e *testEnv) countRows(table string) int {
	e.t.Helper()
	var n int
	// table is a test constant, never user input.
	if err := e.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		e.t.Fatalf("count %s: %v", table, err)
	}
	return n
}

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
)

func TestHealthz(t *testing.T) {
	env := newTestEnv(t)
	r := env.do("GET", "/healthz", "", nil)
	expectStatus(t, r, http.StatusOK, "")
	if ct := r.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body struct{ Status string }
	r.decode(t, &body)
	if body.Status != "ok" {
		t.Errorf("status field = %q, want ok", body.Status)
	}
}

func TestUnknownRoute404(t *testing.T) {
	env := newTestEnv(t)
	expectStatus(t, env.do("GET", "/nope", "", nil), http.StatusNotFound, "")
}

func TestRegisterLoginMe(t *testing.T) {
	env := newTestEnv(t)

	// Email is trimmed and lowercased at the boundary.
	reg := env.register("  Alice@Example.COM ", testPassword, "laptop")
	if reg.User.Email != testEmail {
		t.Errorf("registered email = %q, want %q", reg.User.Email, testEmail)
	}
	if reg.User.ID == "" || reg.AccessToken == "" || reg.RefreshToken == "" {
		t.Fatalf("register response missing fields: %+v", reg)
	}
	if reg.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", reg.TokenType)
	}
	if want := int64(config.DefaultAccessTokenTTL / time.Second); reg.ExpiresIn != want {
		t.Errorf("expires_in = %d, want %d", reg.ExpiresIn, want)
	}
	if want := int64(config.DefaultRefreshTokenTTL / time.Second); reg.RefreshExpiresIn != want {
		t.Errorf("refresh_expires_in = %d, want %d", reg.RefreshExpiresIn, want)
	}
	if !reg.User.CreatedAt.Equal(env.clock.Now()) {
		t.Errorf("created_at = %v, want %v", reg.User.CreatedAt, env.clock.Now())
	}

	// Register auto-logs in: its access token works immediately.
	r := env.do("GET", "/auth/me", reg.AccessToken, nil)
	expectStatus(t, r, http.StatusOK, "")

	login := env.login("ALICE@example.com", testPassword, "phone")
	if login.User.ID != reg.User.ID {
		t.Errorf("login user id = %q, want %q", login.User.ID, reg.User.ID)
	}
	if login.AccessToken == reg.AccessToken || login.RefreshToken == reg.RefreshToken {
		t.Error("login reused tokens from register")
	}

	r = env.do("GET", "/auth/me", login.AccessToken, nil)
	expectStatus(t, r, http.StatusOK, "")
	var me auth.User
	r.decode(t, &me)
	if me.ID != reg.User.ID || me.Email != testEmail {
		t.Errorf("me = %+v, want id %q email %q", me, reg.User.ID, testEmail)
	}
	if strings.Contains(string(r.body), "password") {
		t.Errorf("/auth/me leaks password field: %s", r.body)
	}
}

func TestTokensStoredOnlyAsHashes(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	for _, q := range []struct{ table, token string }{
		{"access_tokens", s.AccessToken},
		{"refresh_tokens", s.RefreshToken},
	} {
		var n int
		err := env.db.QueryRow(`SELECT COUNT(*) FROM `+q.table+` WHERE token_hash = ?`, q.token).Scan(&n)
		if err != nil {
			t.Fatalf("query %s: %v", q.table, err)
		}
		if n != 0 {
			t.Errorf("%s stores the plaintext token", q.table)
		}
	}
	var stored string
	if err := env.db.QueryRow(`SELECT password_hash FROM users`).Scan(&stored); err != nil {
		t.Fatalf("query users: %v", err)
	}
	if !strings.HasPrefix(stored, "$argon2id$") || strings.Contains(stored, testPassword) {
		t.Errorf("password_hash = %q, want an argon2id hash", stored)
	}
}

func TestRegisterValidation(t *testing.T) {
	env := newTestEnv(t)
	cases := map[string]any{
		"missing email":        credentialsRequest{"", testPassword, "laptop"},
		"no at sign":           credentialsRequest{"alice.example.com", testPassword, "laptop"},
		"display name form":    credentialsRequest{"Alice <alice@example.com>", testPassword, "laptop"},
		"no domain":            credentialsRequest{"alice@", testPassword, "laptop"},
		"short password":       credentialsRequest{testEmail, "1234567", "laptop"},
		"short multibyte pass": credentialsRequest{testEmail, "ééééééé", "laptop"}, // 14 bytes, 7 chars
		"huge password":        credentialsRequest{testEmail, strings.Repeat("x", maxPasswordBytes+1), "laptop"},
		"missing device":       credentialsRequest{testEmail, testPassword, "   "},
		"long device":          credentialsRequest{testEmail, testPassword, strings.Repeat("d", maxDeviceNameChars+1)},
		"malformed json":       `{"email":`,
		"not an object":        `[]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := env.do("POST", "/auth/register", "", body)
			expectStatus(t, r, http.StatusBadRequest, codeInvalidRequest)
		})
	}
	if n := env.countRows("users"); n != 0 {
		t.Errorf("%d users created by invalid requests", n)
	}

	// Exactly 8 characters is accepted.
	env.register(testEmail, "12345678", "laptop")
}

func TestRegisterDuplicateEmail409(t *testing.T) {
	env := newTestEnv(t)
	env.register(testEmail, testPassword, "laptop")
	r := env.do("POST", "/auth/register", "", credentialsRequest{" ALICE@example.com", "another password", "phone"})
	expectStatus(t, r, http.StatusConflict, codeEmailTaken)
	if n := env.countRows("users"); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}
}

func TestLoginWrongPassword401(t *testing.T) {
	env := newTestEnv(t)
	env.register(testEmail, testPassword, "laptop")
	before := env.countRows("access_tokens")

	wrong := env.do("POST", "/auth/login", "", credentialsRequest{testEmail, "wrong password", "phone"})
	expectStatus(t, wrong, http.StatusUnauthorized, codeInvalidCredentials)

	// Unknown email is indistinguishable from a wrong password.
	unknown := env.do("POST", "/auth/login", "", credentialsRequest{"bob@example.com", "wrong password", "phone"})
	expectStatus(t, unknown, http.StatusUnauthorized, codeInvalidCredentials)
	if !bytes.Equal(wrong.body, unknown.body) {
		t.Errorf("bodies differ: wrong password %s vs unknown email %s", wrong.body, unknown.body)
	}

	if after := env.countRows("access_tokens"); after != before {
		t.Errorf("failed logins issued tokens: %d -> %d", before, after)
	}
}

func TestMiddlewareRejectsBadTokens(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	cases := map[string]string{
		"no header":         "",
		"wrong scheme":      "Basic " + s.AccessToken,
		"scheme only":       "Bearer",
		"empty token":       "Bearer   ",
		"garbage token":     "Bearer not-a-real-token",
		"refresh as access": "Bearer " + s.RefreshToken,
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", env.srv.URL+"/auth/me", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			resp, err := env.srv.Client().Do(req)
			if err != nil {
				t.Fatalf("GET /auth/me: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			expectStatus(t, response{resp.StatusCode, resp.Header, body}, http.StatusUnauthorized, codeInvalidToken)
		})
	}

	// The scheme is case-insensitive (RFC 7235).
	req, _ := http.NewRequest("GET", env.srv.URL+"/auth/me", nil)
	req.Header.Set("Authorization", "bearer "+s.AccessToken)
	resp, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /auth/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("lowercase bearer scheme: status = %d, want 200", resp.StatusCode)
	}
}

func TestExpiredAccessToken401(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	env.clock.Advance(config.DefaultAccessTokenTTL - time.Second)
	expectStatus(t, env.do("GET", "/auth/me", s.AccessToken, nil), http.StatusOK, "")

	env.clock.Advance(time.Second)
	expectStatus(t, env.do("GET", "/auth/me", s.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)

	// The refresh token outlives it and gets the client a working pair.
	r := env.refresh(s.RefreshToken)
	expectStatus(t, r, http.StatusOK, "")
	var fresh tokenResponse
	r.decode(t, &fresh)
	expectStatus(t, env.do("GET", "/auth/me", fresh.AccessToken, nil), http.StatusOK, "")
}

func TestExpiredRefreshToken401(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	env.clock.Advance(config.DefaultRefreshTokenTTL)
	expectStatus(t, env.refresh(s.RefreshToken), http.StatusUnauthorized, codeInvalidToken)
}

func TestRefreshRotation(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	refresh := s.RefreshToken
	seen := map[string]bool{s.AccessToken: true, refresh: true}
	for i := range 3 {
		env.clock.Advance(10 * time.Minute)
		r := env.refresh(refresh)
		expectStatus(t, r, http.StatusOK, "")
		var next tokenResponse
		r.decode(t, &next)

		if seen[next.AccessToken] || seen[next.RefreshToken] {
			t.Fatalf("rotation %d returned a previously issued token", i)
		}
		seen[next.AccessToken], seen[next.RefreshToken] = true, true
		if next.TokenType != "Bearer" || next.ExpiresIn <= 0 || next.RefreshExpiresIn <= 0 {
			t.Errorf("rotation %d: bad token metadata %+v", i, next)
		}

		r = env.do("GET", "/auth/me", next.AccessToken, nil)
		expectStatus(t, r, http.StatusOK, "")
		var me auth.User
		r.decode(t, &me)
		if me.ID != s.User.ID {
			t.Errorf("rotation %d: me.id = %q, want %q", i, me.ID, s.User.ID)
		}
		refresh = next.RefreshToken
	}

	// Redeemed refresh tokens are kept (marked used) for reuse detection;
	// exactly one per chain is still live.
	var live int
	if err := env.db.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE last_used_at IS NULL`).Scan(&live); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	if live != 1 {
		t.Errorf("live refresh tokens = %d, want 1", live)
	}
}

// A client whose refresh response was lost retries with the same token.
// Inside the retry grace window that gets a fresh pair, not a 401.
func TestRefreshRetryWithinGrace(t *testing.T) {
	env := newTestEnv(t)
	s := env.register(testEmail, testPassword, "laptop")

	r := env.refresh(s.RefreshToken)
	expectStatus(t, r, http.StatusOK, "")
	var rotated tokenResponse
	r.decode(t, &rotated)

	// Immediate retry with the token that was just redeemed.
	r = env.refresh(s.RefreshToken)
	expectStatus(t, r, http.StatusOK, "")
	var retried tokenResponse
	r.decode(t, &retried)
	if retried.RefreshToken == rotated.RefreshToken || retried.RefreshToken == s.RefreshToken {
		t.Errorf("retry returned an already issued refresh token")
	}

	// The session is fully alive: the retry's pair works and the chain keeps
	// rotating.
	expectStatus(t, env.do("GET", "/auth/me", retried.AccessToken, nil), http.StatusOK, "")
	expectStatus(t, env.refresh(retried.RefreshToken), http.StatusOK, "")

	// Once the window has passed, the old token is a stolen-token replay.
	env.clock.Advance(auth.RefreshRetryGrace + time.Second)
	expectStatus(t, env.refresh(s.RefreshToken), http.StatusUnauthorized, codeTokenReused)
}

func TestRefreshValidation(t *testing.T) {
	env := newTestEnv(t)
	expectStatus(t, env.refresh(""), http.StatusBadRequest, codeInvalidRequest)
	expectStatus(t, env.do("POST", "/auth/refresh", "", `nope`), http.StatusBadRequest, codeInvalidRequest)
	expectStatus(t, env.refresh("never-issued"), http.StatusUnauthorized, codeInvalidToken)
}

func TestRefreshReuseRevokesChain(t *testing.T) {
	env := newTestEnv(t)
	laptop := env.register(testEmail, testPassword, "laptop")
	phone := env.login(testEmail, testPassword, "phone")

	// Legitimate rotation on the laptop: r1 -> r2.
	r := env.refresh(laptop.RefreshToken)
	expectStatus(t, r, http.StatusOK, "")
	var rotated tokenResponse
	r.decode(t, &rotated)

	// Move past the retry grace window so the replay below is theft, not a
	// network retry of a lost response.
	env.clock.Advance(auth.RefreshRetryGrace + time.Second)

	// Someone presents r1 again (the attacker, or the victim after the
	// attacker already rotated it). Either way the session is compromised.
	expectStatus(t, env.refresh(laptop.RefreshToken), http.StatusUnauthorized, codeTokenReused)

	// Every laptop token is dead: the newest refresh token...
	expectStatus(t, env.refresh(rotated.RefreshToken), http.StatusUnauthorized, codeInvalidToken)
	// ...and both access tokens issued on that chain.
	expectStatus(t, env.do("GET", "/auth/me", rotated.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)
	expectStatus(t, env.do("GET", "/auth/me", laptop.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)
	// Replaying r1 again is now just an unknown token.
	expectStatus(t, env.refresh(laptop.RefreshToken), http.StatusUnauthorized, codeInvalidToken)

	// Other devices of the same user are unaffected.
	expectStatus(t, env.do("GET", "/auth/me", phone.AccessToken, nil), http.StatusOK, "")
	expectStatus(t, env.refresh(phone.RefreshToken), http.StatusOK, "")

	// The laptop recovers by logging in again.
	again := env.login(testEmail, testPassword, "laptop")
	expectStatus(t, env.do("GET", "/auth/me", again.AccessToken, nil), http.StatusOK, "")
}

func TestLogoutKillsTokens(t *testing.T) {
	env := newTestEnv(t)
	laptop := env.register(testEmail, testPassword, "laptop")
	phone := env.login(testEmail, testPassword, "phone")

	r := env.do("POST", "/auth/logout", laptop.AccessToken, nil)
	expectStatus(t, r, http.StatusNoContent, "")
	if len(r.body) != 0 {
		t.Errorf("logout body = %q, want empty", r.body)
	}

	expectStatus(t, env.do("GET", "/auth/me", laptop.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)
	expectStatus(t, env.refresh(laptop.RefreshToken), http.StatusUnauthorized, codeInvalidToken)
	expectStatus(t, env.do("POST", "/auth/logout", laptop.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)

	// Logout is per session.
	expectStatus(t, env.do("GET", "/auth/me", phone.AccessToken, nil), http.StatusOK, "")
}

// A second login on the same device name is a separate session; logging one
// out must not touch the other.
func TestLogoutSparesOtherSessionsOnTheSameDeviceName(t *testing.T) {
	env := newTestEnv(t)
	first := env.register(testEmail, testPassword, "phone")
	second := env.login(testEmail, testPassword, "phone")

	expectStatus(t, env.do("POST", "/auth/logout", first.AccessToken, nil), http.StatusNoContent, "")

	expectStatus(t, env.do("GET", "/auth/me", first.AccessToken, nil), http.StatusUnauthorized, codeInvalidToken)
	expectStatus(t, env.refresh(first.RefreshToken), http.StatusUnauthorized, codeInvalidToken)

	// The second login on the same device name keeps working.
	expectStatus(t, env.do("GET", "/auth/me", second.AccessToken, nil), http.StatusOK, "")
	expectStatus(t, env.refresh(second.RefreshToken), http.StatusOK, "")
}

func TestLogoutRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	expectStatus(t, env.do("POST", "/auth/logout", "", nil), http.StatusUnauthorized, codeInvalidToken)
}

func TestExpiredTokensPrunedOnIssue(t *testing.T) {
	env := newTestEnv(t)
	env.register(testEmail, testPassword, "laptop")
	env.login(testEmail, testPassword, "phone")
	if n := env.countRows("access_tokens"); n != 2 {
		t.Fatalf("access_tokens = %d, want 2", n)
	}

	env.clock.Advance(config.DefaultRefreshTokenTTL)
	env.login(testEmail, testPassword, "tablet")
	if n := env.countRows("access_tokens"); n != 1 {
		t.Errorf("access_tokens = %d after prune, want 1", n)
	}
	if n := env.countRows("refresh_tokens"); n != 1 {
		t.Errorf("refresh_tokens = %d after prune, want 1", n)
	}
}

func TestBodyTooLarge(t *testing.T) {
	env := newTestEnv(t)
	big := `{"email":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`
	expectStatus(t, env.do("POST", "/auth/login", "", big), http.StatusBadRequest, codeInvalidRequest)
}
