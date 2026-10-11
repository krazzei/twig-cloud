// Package auth implements accounts and sessions: argon2id password hashing,
// opaque bearer tokens (hashed at rest), and rotating refresh tokens with
// reuse detection.
//
// A session is one login on one device, identified by a session_id that
// every token issued on it carries. device_name is informational; two
// logins that happen to share a name are separate sessions. Every refresh
// redeems the presented refresh token (stamping last_used_at) and issues a
// new pair on the same session.
//
// Redeemed rows are kept until they expire so a second presentation of the
// same token is recognised. If it arrives within RefreshRetryGrace of the
// original redemption it is treated as a network retry of a refresh whose
// response was lost, and a fresh pair is issued. Otherwise the token must
// have been copied, and every access and refresh token of the session is
// revoked.
//
// Input validation (email format, password length, device name) belongs to
// the HTTP boundary; this package trusts its callers to pass normalised
// values.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"uuid"

	"github.com/twig/twig-cloud/internal/database"
)

var (
	// ErrEmailTaken: Register was called with an email that already exists.
	ErrEmailTaken = errors.New("auth: email already registered")
	// ErrInvalidCredentials: unknown email or wrong password. Deliberately
	// does not say which.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	// ErrInvalidToken: a token is unknown, expired, or revoked.
	ErrInvalidToken = errors.New("auth: invalid or expired token")
	// ErrTokenReused: an already-rotated refresh token was presented. The
	// device's whole session chain has been revoked as a result.
	ErrTokenReused = errors.New("auth: refresh token reuse detected")
	// ErrUserNotFound: no user with the given id.
	ErrUserNotFound = errors.New("auth: user not found")
)

// RefreshRetryGrace bounds how long an already-redeemed refresh token is
// still accepted as a retry. A client whose refresh response was lost by
// the network re-sends the same token; within this window that is re-issued
// instead of treated as theft. The window is short on purpose: a replayed
// stolen token is only usable inside it.
const RefreshRetryGrace = 60 * time.Second

// User is the public view of an account (no password hash).
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// Tokens is a freshly issued access/refresh pair. The plaintext tokens exist
// only here; the database holds their SHA-256.
type Tokens struct {
	IssuedAt         time.Time
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// Session is what a valid access token resolves to. SessionID identifies
// the login the token was issued on; logout and reuse revocation scope to
// it, not to the device name.
type Session struct {
	UserID     string
	SessionID  string
	DeviceName string
}

// Options configures a Service.
type Options struct {
	AccessTTL  time.Duration    // required; normally config.AccessTokenTTL
	RefreshTTL time.Duration    // required; normally config.RefreshTokenTTL
	Now        func() time.Time // nil = time.Now; tests inject a fake clock
	Logger     *slog.Logger     // nil = slog.Default()
}

// Service is safe for concurrent use.
type Service struct {
	db         *database.DB
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
	logger     *slog.Logger

	// dummyHash is verified against when a login names an unknown email, so
	// that path costs the same argon2 work as a wrong password and response
	// timing doesn't reveal which emails are registered.
	dummyHash func() string
}

// NewService returns a Service backed by db, which must be migrated.
func NewService(db *database.DB, opts Options) (*Service, error) {
	if db == nil {
		return nil, errors.New("auth: nil database")
	}
	if opts.AccessTTL <= 0 || opts.RefreshTTL <= 0 {
		return nil, fmt.Errorf("auth: token TTLs must be positive (access %v, refresh %v)",
			opts.AccessTTL, opts.RefreshTTL)
	}
	s := &Service{
		db:         db,
		accessTTL:  opts.AccessTTL,
		refreshTTL: opts.RefreshTTL,
		now:        opts.Now,
		logger:     opts.Logger,
		dummyHash:  sync.OnceValue(func() string { return HashPassword("twig-cloud-dummy-password") }),
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

// Register creates a user and logs them in on deviceName.
func (s *Service) Register(ctx context.Context, email, password, deviceName string) (User, Tokens, error) {
	// Hash before opening the transaction: it's the slow part, and
	// transactions hold SQLite's write lock from BEGIN.
	hash := HashPassword(password)
	now := s.now()
	u := User{ID: uuid.New().String(), Email: email, CreatedAt: time.Unix(now.Unix(), 0).UTC()}

	var tokens Tokens
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
			u.ID, u.Email, hash, now.Unix())
		if database.IsUniqueViolation(err) {
			return ErrEmailTaken
		}
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}
		tokens, err = s.issue(ctx, tx, u.ID, uuid.New().String(), deviceName, now)
		return err
	})
	if err != nil {
		return User{}, Tokens{}, err
	}
	return u, tokens, nil
}

// Login checks credentials and starts a new session on deviceName.
func (s *Service) Login(ctx context.Context, email, password, deviceName string) (User, Tokens, error) {
	var (
		u         User
		hash      string
		createdAt int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, email).
		Scan(&u.ID, &u.Email, &hash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = VerifyPassword(s.dummyHash(), password)
		return User{}, Tokens{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, Tokens{}, fmt.Errorf("look up user: %w", err)
	}
	u.CreatedAt = time.Unix(createdAt, 0).UTC()

	ok, err := VerifyPassword(hash, password)
	if err != nil {
		return User{}, Tokens{}, fmt.Errorf("user %s: %w", u.ID, err)
	}
	if !ok {
		return User{}, Tokens{}, ErrInvalidCredentials
	}

	var tokens Tokens
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		tokens, err = s.issue(ctx, tx, u.ID, uuid.New().String(), deviceName, s.now())
		return err
	})
	if err != nil {
		return User{}, Tokens{}, err
	}
	return u, tokens, nil
}

// Refresh redeems refreshToken for a new token pair on the same session.
//
// It returns ErrInvalidToken for unknown or expired tokens, and
// ErrTokenReused (after revoking the session) for tokens that were already
// redeemed more than RefreshRetryGrace ago. A redemption inside that window
// is a retry of a refresh whose response was lost and simply gets a fresh
// pair.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	tokenHash := hashToken(refreshToken)
	now := s.now()

	var (
		tokens  Tokens
		outcome error // a rejection whose side effects (revocation) must still commit
		reuser  Session
	)
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var (
			sess      Session
			expiresAt int64
			usedAt    sql.NullInt64
		)
		err := tx.QueryRowContext(ctx,
			`SELECT user_id, session_id, device_name, expires_at, last_used_at
			   FROM refresh_tokens WHERE token_hash = ?`, tokenHash).
			Scan(&sess.UserID, &sess.SessionID, &sess.DeviceName, &expiresAt, &usedAt)
		if errors.Is(err, sql.ErrNoRows) {
			outcome = ErrInvalidToken
			return nil
		}
		if err != nil {
			return fmt.Errorf("look up refresh token: %w", err)
		}

		// Reuse is checked before expiry: an old stolen token is still
		// evidence of theft as long as we remember it.
		if usedAt.Valid {
			// The client's refresh succeeded but the response was lost, so
			// it is retrying with the same token. Re-issue instead of
			// revoking; the pair issued by the lost response stays live
			// because we cannot tell which one the client kept.
			if now.Unix()-usedAt.Int64 <= int64(RefreshRetryGrace.Seconds()) {
				tokens, err = s.issue(ctx, tx, sess.UserID, sess.SessionID, sess.DeviceName, now)
				return err
			}
			if err := revokeChain(ctx, tx, sess); err != nil {
				return err
			}
			outcome, reuser = ErrTokenReused, sess
			return nil
		}
		if expiresAt <= now.Unix() {
			outcome = ErrInvalidToken
			return nil
		}

		res, err := tx.ExecContext(ctx,
			`UPDATE refresh_tokens SET last_used_at = ? WHERE token_hash = ? AND last_used_at IS NULL`,
			now.Unix(), tokenHash)
		if err != nil {
			return fmt.Errorf("redeem refresh token: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			// Unreachable while transactions are BEGIN IMMEDIATE (writers are
			// serialised), but never issue tokens on an unredeemed row.
			return fmt.Errorf("redeem refresh token: %d rows affected (%v)", n, err)
		}
		tokens, err = s.issue(ctx, tx, sess.UserID, sess.SessionID, sess.DeviceName, now)
		return err
	})
	if err != nil {
		return Tokens{}, err
	}
	if errors.Is(outcome, ErrTokenReused) {
		s.logger.Warn("refresh token reuse detected; revoked session",
			"user_id", reuser.UserID, "session_id", reuser.SessionID)
	}
	if outcome != nil {
		return Tokens{}, outcome
	}
	return tokens, nil
}

// Authenticate resolves an access token to its session.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, session_id, device_name
		   FROM access_tokens WHERE token_hash = ? AND expires_at > ?`,
		hashToken(accessToken), s.now().Unix()).
		Scan(&sess.UserID, &sess.SessionID, &sess.DeviceName)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrInvalidToken
	}
	if err != nil {
		return Session{}, fmt.Errorf("look up access token: %w", err)
	}
	return sess, nil
}

// Logout ends sess: every access and refresh token issued on that login's
// session is revoked. Other logins, even on the same device name, are
// untouched.
func (s *Service) Logout(ctx context.Context, sess Session) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		return revokeChain(ctx, tx, sess)
	})
}

// User returns the user with the given id.
func (s *Service) User(ctx context.Context, id string) (User, error) {
	var (
		u         User
		createdAt int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, created_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Email, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("look up user: %w", err)
	}
	u.CreatedAt = time.Unix(createdAt, 0).UTC()
	return u, nil
}

// issue inserts a new access/refresh pair on sessionID and, while it holds
// the write lock anyway, prunes the user's expired tokens so the tables stay
// bounded without a background job.
func (s *Service) issue(ctx context.Context, tx *sql.Tx, userID, sessionID, deviceName string, now time.Time) (Tokens, error) {
	t := Tokens{
		IssuedAt:         time.Unix(now.Unix(), 0).UTC(),
		AccessToken:      newToken(),
		AccessExpiresAt:  time.Unix(now.Add(s.accessTTL).Unix(), 0).UTC(),
		RefreshToken:     newToken(),
		RefreshExpiresAt: time.Unix(now.Add(s.refreshTTL).Unix(), 0).UTC(),
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM access_tokens WHERE user_id = ? AND expires_at <= ?`, userID, now.Unix()); err != nil {
		return Tokens{}, fmt.Errorf("prune access tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE user_id = ? AND expires_at <= ?`, userID, now.Unix()); err != nil {
		return Tokens{}, fmt.Errorf("prune refresh tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO access_tokens (token_hash, user_id, session_id, device_name, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		hashToken(t.AccessToken), userID, sessionID, deviceName, t.AccessExpiresAt.Unix(), now.Unix()); err != nil {
		return Tokens{}, fmt.Errorf("insert access token: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, session_id, device_name, expires_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		hashToken(t.RefreshToken), userID, sessionID, deviceName, t.RefreshExpiresAt.Unix()); err != nil {
		return Tokens{}, fmt.Errorf("insert refresh token: %w", err)
	}
	return t, nil
}

// revokeChain deletes every access and refresh token in the session.
func revokeChain(ctx context.Context, tx *sql.Tx, sess Session) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM access_tokens WHERE user_id = ? AND session_id = ?`,
		sess.UserID, sess.SessionID); err != nil {
		return fmt.Errorf("revoke access tokens: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE user_id = ? AND session_id = ?`,
		sess.UserID, sess.SessionID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}
