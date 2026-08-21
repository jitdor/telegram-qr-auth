package telegramqrauth

import (
	"testing"
	"time"
)

// The known-answer vector from the package's own tests/assertions.test.mjs, produced by the
// JavaScript implementation and independently reproduced with Python. If these pass, this port
// agrees with the protocol rather than merely with itself.
const (
	vectorSecret = "123456:AAHfake-bot-token"
	vectorValue  = "eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9" +
		".ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95"
)

func newTestVerifier(t *testing.T, secret string, opts ...VerifierOption) *Verifier {
	t.Helper()
	v, err := NewVerifier(secret, opts...)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerifyKnownAnswer(t *testing.T) {
	session, err := newTestVerifier(t, vectorSecret).Verify(vectorValue)
	if err != nil {
		t.Fatalf("Verify returned %v, want success", err)
	}
	if session.ID != 39644372 {
		t.Errorf("ID = %d, want 39644372", session.ID)
	}
	if session.Name != "Alice Ng" {
		t.Errorf("Name = %q, want %q", session.Name, "Alice Ng")
	}
	if session.Username != "alice" {
		t.Errorf("Username = %q, want %q", session.Username, "alice")
	}
}

func TestVerifyAcceptsBearerPrefix(t *testing.T) {
	v := newTestVerifier(t, vectorSecret)
	for _, prefix := range []string{"Bearer ", "bearer ", "BEARER "} {
		if _, err := v.Verify(prefix + vectorValue); err != nil {
			t.Errorf("Verify(%q + value) = %v, want success", prefix, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	payload, signature, _ := cut(vectorValue)

	cases := []struct {
		name     string
		verifier *Verifier
		value    string
	}{
		{"wrong secret", newTestVerifier(t, "wrong-secret"), vectorValue},
		{"wrong key label", newTestVerifier(t, vectorSecret, WithKeyLabel("SomeOtherLabel")), vectorValue},
		{"tampered payload", newTestVerifier(t, vectorSecret), "eyJpZCI6OTk5fQ." + signature},
		{"tampered signature", newTestVerifier(t, vectorSecret), payload + ".0000000000000000000000000000000000000000000000000000000000000000"},
		{"no signature", newTestVerifier(t, vectorSecret), payload},
		{"empty", newTestVerifier(t, vectorSecret), ""},
		{"junk", newTestVerifier(t, vectorSecret), "nonsense"},
		{"only a dot", newTestVerifier(t, vectorSecret), "."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.verifier.Verify(tc.value); err == nil {
				t.Fatal("Verify succeeded, want failure")
			}
		})
	}
}

func TestVerifyEnforcesExpiry(t *testing.T) {
	// The vector's exp is in 2100, and its signature is valid forever — only the clock stops it.
	afterExpiry := func() time.Time { return time.Unix(4_102_444_801, 0) }
	v := newTestVerifier(t, vectorSecret, WithClock(afterExpiry))

	if _, err := v.Verify(vectorValue); err == nil {
		t.Fatal("an expired session verified, want failure")
	}
}

func TestReadUnverifiedClaimsDoesNotAuthenticate(t *testing.T) {
	// Forged: valid base64url JSON, signature nonsense. Decoding must succeed and verifying must
	// not — this is the trap the doc comment warns about.
	forged := "eyJpZCI6OTk5OTk5LCJuYW1lIjoiTWFsbG9yeSIsImV4cCI6NDEwMjQ0NDgwMH0.deadbeef"

	session, err := ReadUnverifiedClaims(forged)
	if err != nil {
		t.Fatalf("ReadUnverifiedClaims: %v", err)
	}
	if session.Name != "Mallory" {
		t.Errorf("Name = %q, want Mallory", session.Name)
	}
	if _, err := newTestVerifier(t, vectorSecret).Verify(forged); err == nil {
		t.Fatal("forged value verified, want failure")
	}
}

func TestNewVerifierRequiresSecret(t *testing.T) {
	if _, err := NewVerifier(""); err == nil {
		t.Fatal("NewVerifier(\"\") succeeded, want error")
	}
}

func cut(s string) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
