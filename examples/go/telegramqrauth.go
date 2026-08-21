// Package telegramqrauth verifies and drives telegram-qr-auth sign-ins from Go.
//
// Go does not run the package (it is JavaScript) and does not need to. The package's web half runs
// once as a Worker at, say, https://auth.example.com. Go either verifies the signed session it
// issued, or drives a sign-in for a client with no browser.
//
// Standard library only — crypto/hmac, crypto/sha256, encoding/base64, encoding/json.
//
//	key       = HMAC-SHA256(key: keyLabel, msg: secret)     -> 32 raw bytes
//	signature = HMAC-SHA256(key: key,      msg: payloadB64) -> lowercase hex
//	value     = payloadB64 + "." + signature
//
// payloadB64 is unpadded base64url of the claims JSON.
//
// Self-check against the package's own test vector:
//
//	go test ./examples/go/
package telegramqrauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultKeyLabel must match session.keyLabel on the auth service.
const DefaultKeyLabel = "TelegramQrAuthSessionKey"

// Session holds the claims carried by a verified session.
type Session struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	Exp      int64  `json:"exp"`
}

// ExpiresAt reports when the session stops being valid.
func (s Session) ExpiresAt() time.Time { return time.Unix(s.Exp, 0) }

// Verifier checks signed session values locally: no HTTP call, no SDK, two HMACs.
type Verifier struct {
	key []byte
	now func() time.Time
}

// NewVerifier builds a Verifier for the auth service's session.secret.
func NewVerifier(secret string, opts ...VerifierOption) (*Verifier, error) {
	if secret == "" {
		return nil, errors.New("telegramqrauth: secret is required")
	}
	v := &Verifier{now: time.Now}
	label := DefaultKeyLabel
	for _, opt := range opts {
		label = opt(v, label)
	}

	// Domain separation: the label is the HMAC key and the secret is the message, so a signature
	// produced under a different label cannot verify here.
	mac := hmac.New(sha256.New, []byte(label))
	mac.Write([]byte(secret))
	v.key = mac.Sum(nil)
	return v, nil
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier, string) string

// WithKeyLabel overrides the HMAC domain-separation label.
func WithKeyLabel(label string) VerifierOption {
	return func(_ *Verifier, _ string) string { return label }
}

// WithClock replaces the clock used for expiry checks. Tests only.
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier, label string) string {
		v.now = now
		return label
	}
}

// ErrInvalidSession is returned for anything that does not verify: bad format, bad signature, or
// expired. The cases are deliberately not distinguished — telling a caller *why* their token failed
// is a small oracle and never actionable.
var ErrInvalidSession = errors.New("telegramqrauth: invalid session")

// Verify returns the claims if value is validly signed and unexpired.
// It accepts a bare value or an "Authorization: Bearer ..." header value.
func (v *Verifier) Verify(value string) (Session, error) {
	var zero Session
	if value == "" {
		return zero, ErrInvalidSession
	}
	if len(value) > 7 && strings.EqualFold(value[:7], "bearer ") {
		value = strings.TrimSpace(value[7:])
	}

	payloadB64, signature, found := strings.Cut(value, ".")
	if !found || payloadB64 == "" || signature == "" {
		return zero, ErrInvalidSession
	}

	// Sign the encoded payload, never the decoded JSON: re-marshalling would reorder keys and no
	// signature would ever match.
	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(payloadB64))
	expected := hex.EncodeToString(mac.Sum(nil))

	// hmac.Equal, not ==: a plain comparison leaks the signature a byte at a time under timing.
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return zero, ErrInvalidSession
	}

	session, err := ReadUnverifiedClaims(value)
	if err != nil || session.ID == 0 {
		return zero, ErrInvalidSession
	}

	// The signature never expires on its own. A verifier that skips this has built a permanent
	// credential.
	if session.Exp < v.now().Unix() {
		return zero, ErrInvalidSession
	}

	return session, nil
}

// ReadUnverifiedClaims decodes the claims WITHOUT checking the signature.
//
// Fine for showing a name in a UI. Never for an access decision: anyone can write anything into
// this half of the string.
func ReadUnverifiedClaims(value string) (Session, error) {
	var session Session
	payloadB64, _, _ := strings.Cut(value, ".")

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		// Tolerate a padded encoder on the other side even though this package does not use one.
		payload, err = base64.URLEncoding.DecodeString(payloadB64)
		if err != nil {
			return session, fmt.Errorf("telegramqrauth: bad payload encoding: %w", err)
		}
	}
	if err := json.Unmarshal(payload, &session); err != nil {
		return session, fmt.Errorf("telegramqrauth: bad payload json: %w", err)
	}
	return session, nil
}

// Middleware guards an http.Handler. It reads a bearer header first, then the cookie — the cookie
// only reaches this app if the auth service shares a registrable domain with it and was configured
// with session.domain.
func (v *Verifier) Middleware(cookieName string, onUnauthorized http.HandlerFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			value := r.Header.Get("Authorization")
			if value == "" {
				if cookie, err := r.Cookie(cookieName); err == nil {
					value = cookie.Value
				}
			}

			session, err := v.Verify(value)
			if err != nil {
				if onUnauthorized != nil {
					onUnauthorized(w, r)
				} else {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
		})
	}
}

type sessionKey struct{}

// FromContext returns the session Middleware stored on the request.
func FromContext(ctx context.Context) (Session, bool) {
	session, ok := ctx.Value(sessionKey{}).(Session)
	return session, ok
}

// -------------------------------------------------------------------------------------------------
// Client — for a CLI or daemon signing a human in.
//
// Needs allowAssertions: true on the auth service, which is off by default: it returns the signed
// session in the body instead of an HttpOnly cookie, appropriate only for clients with no cookie jar.
// -------------------------------------------------------------------------------------------------

// Challenge is what the auth service hands back when a sign-in starts.
type Challenge struct {
	Token     string `json:"token"`
	DeepLink  string `json:"deepLink"`
	SVG       string `json:"svg"`
	ExpiresIn int    `json:"expiresIn"`
	PollPath  string `json:"pollPath"`
}

// Client drives the QR sign-in against an auth service.
type Client struct {
	AuthBase string
	HTTP     *http.Client
	Interval time.Duration
}

// NewClient returns a Client with sensible defaults.
func NewClient(authBase string) *Client {
	return &Client{
		AuthBase: strings.TrimRight(authBase, "/"),
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Interval: 2 * time.Second,
	}
}

// Begin asks for a fresh challenge to display.
func (c *Client) Begin(ctx context.Context) (Challenge, error) {
	var challenge Challenge
	if err := c.getJSON(ctx, c.AuthBase+"/auth/qr", &challenge); err != nil {
		return challenge, err
	}
	if challenge.Token == "" {
		return challenge, errors.New("telegramqrauth: auth service returned no challenge")
	}
	return challenge, nil
}

// SignInError reports a sign-in that ended in anything other than success.
type SignInError struct {
	Status string
	Reason string
}

func (e *SignInError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("telegramqrauth: sign-in %s: %s", e.Status, e.Reason)
	}
	return "telegramqrauth: sign-in " + e.Status
}

// WaitForScan polls until the user scans, the token expires, or ctx is done. On success it returns
// the assertion to store and the claims it carries.
func (c *Client) WaitForScan(ctx context.Context, token string) (string, Session, error) {
	pollURL := fmt.Sprintf("%s/auth/poll?token=%s&mode=token", c.AuthBase, url.QueryEscape(token))

	for {
		var body struct {
			Status    string `json:"status"`
			Assertion string `json:"assertion"`
			Reason    string `json:"reason"`
			Error     string `json:"error"`
		}
		if err := c.getJSON(ctx, pollURL, &body); err != nil {
			return "", Session{}, err
		}

		switch body.Status {
		case "confirmed":
			session, err := ReadUnverifiedClaims(body.Assertion)
			if err != nil {
				return "", Session{}, err
			}
			return body.Assertion, session, nil

		case "denied", "expired", "invalid":
			// "invalid" is also what you get if allowAssertions is off on the service.
			reason := body.Reason
			if reason == "" {
				reason = body.Error
			}
			return "", Session{}, &SignInError{Status: body.Status, Reason: reason}
		}

		// "pending" — the QR is on screen and nobody has scanned it yet.
		select {
		case <-ctx.Done():
			return "", Session{}, ctx.Err()
		case <-time.After(c.Interval):
		}
	}
}

func (c *Client) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// A 400 here still carries a useful JSON body (for example, assertion mode disabled), so decode
	// before deciding this was a failure.
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("telegramqrauth: %s returned %s: %w", endpoint, resp.Status, err)
	}
	return nil
}
