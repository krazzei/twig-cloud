package auth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twig/twig-cloud/internal/database"
	"golang.org/x/crypto/argon2"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	h := HashPassword("hunter2hunter2")

	wantPrefix := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", argon2Memory, argon2Time, argon2Threads)
	if !strings.HasPrefix(h, wantPrefix) {
		t.Fatalf("hash %q does not start with %q", h, wantPrefix)
	}
	if ok, err := VerifyPassword(h, "hunter2hunter2"); err != nil || !ok {
		t.Fatalf("VerifyPassword(correct) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := VerifyPassword(h, "hunter2hunter3"); err != nil || ok {
		t.Fatalf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
	if h2 := HashPassword("hunter2hunter2"); h2 == h {
		t.Fatal("two hashes of the same password are identical; salt not random")
	}
}

func TestVerifyPasswordUsesEncodedParams(t *testing.T) {
	// A hash made with different (cheaper) parameters must still verify,
	// so the constants can be retuned without locking out existing users.
	salt := []byte("saltsaltsaltsalt")
	key := argon2.IDKey([]byte("pw-pw-pw-pw"), salt, 1, 8192, 1, 32)
	old := fmt.Sprintf("$argon2id$v=19$m=8192,t=1,p=1$%s$%s", b64.EncodeToString(salt), b64.EncodeToString(key))
	if ok, err := VerifyPassword(old, "pw-pw-pw-pw"); err != nil || !ok {
		t.Fatalf("VerifyPassword(old params) = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, h := range []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$a2V5",
		"$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$a2V5",
		"$argon2id$v=19$m=0,t=3,p=4$c2FsdA$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA",
	} {
		if _, err := VerifyPassword(h, "x"); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("VerifyPassword(%q) err = %v, want ErrMalformedHash", h, err)
		}
	}
}

func TestNewToken(t *testing.T) {
	a, b := newToken(), newToken()
	if a == b {
		t.Fatal("two tokens are identical")
	}
	if len(a) != 43 { // base64url(32 bytes), unpadded
		t.Errorf("token length = %d, want 43", len(a))
	}
	if h := hashToken(a); len(h) != 64 || h == a || h != hashToken(a) {
		t.Errorf("hashToken(%q) = %q, want stable 64-char hex", a, h)
	}
}

func TestNewServiceValidatesOptions(t *testing.T) {
	db := openDB(t)
	if _, err := NewService(nil, Options{AccessTTL: time.Minute, RefreshTTL: time.Hour}); err == nil {
		t.Error("NewService(nil db) succeeded")
	}
	if _, err := NewService(db, Options{AccessTTL: 0, RefreshTTL: time.Hour}); err == nil {
		t.Error("NewService(zero access TTL) succeeded")
	}
	if _, err := NewService(db, Options{AccessTTL: time.Minute, RefreshTTL: -time.Hour}); err == nil {
		t.Error("NewService(negative refresh TTL) succeeded")
	}
}

// TestReuseRevocationCommits guards against the easy mistake of returning an
// error from inside the transaction, which would roll the revocation back.
// testClock is a manually advanced clock for service tests.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestService(t *testing.T, clock *testClock) (*Service, *database.DB) {
	t.Helper()
	db := openDB(t)
	// Access TTL longer than RefreshRetryGrace so tests that advance past
	// the grace window don't expire access tokens along the way.
	svc, err := NewService(db, Options{
		AccessTTL:  15 * time.Minute,
		RefreshTTL: time.Hour,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, db
}

func TestReuseRevocationCommits(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, db := newTestService(t, clock)
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "dev")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Refresh(ctx, first.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Past the retry grace window: the replayed token is theft, not a retry.
	clock.Advance(RefreshRetryGrace + time.Second)
	if _, err := svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("second Refresh err = %v, want ErrTokenReused", err)
	}
	for _, table := range []string{"access_tokens", "refresh_tokens"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after reuse revocation, want 0", table, n)
		}
	}
}

// A refresh whose response was lost is retried with the same token; inside
// the grace window that re-issues a pair instead of revoking the session.
func TestRefreshRetryWithinGrace(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, _ := newTestService(t, clock)
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "dev")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	second, err := svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// The client never received "second" and retries with the old token.
	clock.Advance(5 * time.Second)
	third, err := svc.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("retry Refresh err = %v, want a fresh pair", err)
	}
	if third.RefreshToken == second.RefreshToken || third.RefreshToken == first.RefreshToken {
		t.Error("retry returned an already issued refresh token")
	}

	// The session is alive: the retry's tokens work, and so does the pair
	// issued by the response the client lost (we cannot tell which one it
	// kept, so both stay valid).
	if _, err := svc.Authenticate(ctx, third.AccessToken); err != nil {
		t.Errorf("Authenticate(retry access) = %v, want ok", err)
	}
	if _, err := svc.Refresh(ctx, second.RefreshToken); err != nil {
		t.Errorf("Refresh(lost pair) = %v, want ok", err)
	}
}

// Two logins that share a device name are separate sessions: a replayed
// token revokes only the session it belongs to.
func TestReuseRevokesOnlyThePresentingSession(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, _ := newTestService(t, clock)
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "phone")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, second, err := svc.Login(ctx, "a@b.c", "password1", "phone") // same name, new session
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := svc.Refresh(ctx, first.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	clock.Advance(RefreshRetryGrace + time.Second)
	if _, err := svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("replay err = %v, want ErrTokenReused", err)
	}

	// The replayed session is dead...
	if _, err := svc.Authenticate(ctx, first.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Authenticate(revoked session) = %v, want ErrInvalidToken", err)
	}
	// ...but the other login on the same device name is not.
	if _, err := svc.Authenticate(ctx, second.AccessToken); err != nil {
		t.Errorf("Authenticate(same-name session) = %v, want ok", err)
	}
	if _, err := svc.Refresh(ctx, second.RefreshToken); err != nil {
		t.Errorf("Refresh(same-name session) = %v, want ok", err)
	}
}

// Logout ends the session the bearer token belongs to, not every login on
// that device name.
func TestLogoutEndsOnlyThePresentingSession(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "phone")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, second, err := svc.Login(ctx, "a@b.c", "password1", "phone")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	sess, err := svc.Authenticate(ctx, first.AccessToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := svc.Logout(ctx, sess); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := svc.Authenticate(ctx, first.AccessToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Authenticate(logged-out session) = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.Authenticate(ctx, second.AccessToken); err != nil {
		t.Errorf("Authenticate(same-name session) = %v, want ok", err)
	}
	if _, err := svc.Refresh(ctx, second.RefreshToken); err != nil {
		t.Errorf("Refresh(same-name session) = %v, want ok", err)
	}
}

// The service's public error contract: what each call returns on its
// rejection paths, independent of any HTTP layer.
func TestServiceErrorContract(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t, &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})

	if _, _, err := svc.Register(ctx, "a@b.c", "password1", "dev"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, _, err := svc.Register(ctx, "a@b.c", "password1", "dev"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate Register err = %v, want ErrEmailTaken", err)
	}
	if _, _, err := svc.Login(ctx, "a@b.c", "wrong-password", "dev"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(wrong password) err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, "ghost@b.c", "wrong-password", "dev"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login(unknown email) err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.Refresh(ctx, "never-issued"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Refresh(unknown token) err = %v, want ErrInvalidToken", err)
	}
	if _, err := svc.User(ctx, "ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("User(unknown id) err = %v, want ErrUserNotFound", err)
	}
}

// Simultaneous presentation of the same redeemed token (two tabs, a retry
// racing the original) must not revoke: BEGIN IMMEDIATE serialises the
// writers, so the first call stamps the row and the rest land inside the
// retry grace window and get fresh pairs.
func TestConcurrentPresentationOfSameToken(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, _ := newTestService(t, clock)
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "dev")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Refresh(ctx, first.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	const n = 5
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		tokens []Tokens
		fails  int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tk, err := svc.Refresh(ctx, first.RefreshToken)
			if err != nil {
				mu.Lock()
				fails++
				mu.Unlock()
				return
			}
			mu.Lock()
			tokens = append(tokens, tk)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if fails != 0 {
		t.Fatalf("%d of %d concurrent presentations failed", fails, n)
	}
	seen := map[string]bool{first.AccessToken: true, first.RefreshToken: true}
	for _, tk := range tokens {
		if seen[tk.AccessToken] || seen[tk.RefreshToken] {
			t.Fatalf("concurrent presentation reused an already issued token")
		}
		seen[tk.AccessToken], seen[tk.RefreshToken] = true, true
		if _, err := svc.Authenticate(ctx, tk.AccessToken); err != nil {
			t.Errorf("Authenticate(concurrent pair) = %v, want ok", err)
		}
	}

	// The storm did not count as theft: past the (fixed) window the old
	// token is still a replay and revokes the session.
	clock.Advance(RefreshRetryGrace + time.Second)
	if _, err := svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrTokenReused) {
		t.Errorf("post-storm replay err = %v, want ErrTokenReused", err)
	}
}

// The grace window is measured from the FIRST redemption and does not slide:
// a retry inside the window issues a pair but does not reset the clock, so a
// presentation just past the original window is always theft. Sliding would
// let an attacker replay one stolen token forever, every 59s. The boundary
// is inclusive: exactly RefreshRetryGrace after redemption is still a retry.
func TestGraceWindowIsFixedNotSliding(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, _ := newTestService(t, clock)
	_, first, err := svc.Register(ctx, "a@b.c", "password1", "dev")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Refresh(ctx, first.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Exactly at the boundary: still a retry.
	clock.Advance(RefreshRetryGrace)
	if _, err := svc.Refresh(ctx, first.RefreshToken); err != nil {
		t.Fatalf("retry at exactly the grace boundary = %v, want a fresh pair", err)
	}

	// One second past: the boundary retry did not reset the clock.
	clock.Advance(time.Second)
	if _, err := svc.Refresh(ctx, first.RefreshToken); !errors.Is(err, ErrTokenReused) {
		t.Fatalf("replay past grace err = %v, want ErrTokenReused (window must not slide)", err)
	}
}

func openDB(t *testing.T) *database.DB {
	t.Helper()
	ctx := context.Background()
	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "twig.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}
