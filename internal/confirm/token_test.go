package confirm

import (
	"errors"
	"testing"
	"time"
)

type args struct {
	Domain string `json:"domain"`
	Kind   string `json:"kind"`
}

func mgr(t *testing.T, secret string) (*Manager, *time.Time) {
	t.Helper()
	m, err := New(secret, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	m.SetClock(func() time.Time { return now })
	return m, &now
}

func TestRoundTrip(t *testing.T) {
	m, _ := mgr(t, "s")
	tok, exp, err := m.Issue("home", "add_domain_rule", args{"a.example", "exact"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.Unix() != 1_700_000_300 {
		t.Fatalf("expiry %v", exp)
	}
	if err := m.Verify(tok, "home", "add_domain_rule", args{"a.example", "exact"}); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingRejected(t *testing.T) {
	m, _ := mgr(t, "s")
	tok, _, _ := m.Issue("home", "add_domain_rule", args{"a.example", "exact"})
	for name, fn := range map[string]func() error{
		"args":     func() error { return m.Verify(tok, "home", "add_domain_rule", args{"b.example", "exact"}) },
		"tool":     func() error { return m.Verify(tok, "home", "remove_domain_rule", args{"a.example", "exact"}) },
		"instance": func() error { return m.Verify(tok, "other", "add_domain_rule", args{"a.example", "exact"}) },
	} {
		if err := fn(); !errors.Is(err, ErrMismatch) {
			t.Errorf("%s: want ErrMismatch, got %v", name, err)
		}
	}
	// extending expiry invalidates the signature
	if err := m.Verify("9999999999"+tok[10:], "home", "add_domain_rule", args{"a.example", "exact"}); !errors.Is(err, ErrMismatch) {
		t.Errorf("expiry tamper: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	m, now := mgr(t, "s")
	tok, _, _ := m.Issue("home", "t", args{})
	*now = now.Add(5*time.Minute + time.Second)
	if err := m.Verify(tok, "home", "t", args{}); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestMalformedAndWrongSecret(t *testing.T) {
	m, _ := mgr(t, "s")
	for _, bad := range []string{"", "abc", "x.y", "123.!!!"} {
		if err := m.Verify(bad, "i", "t", args{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: want malformed, got %v", bad, err)
		}
	}
	tok, _, _ := m.Issue("i", "t", args{})
	other, _ := mgr(t, "different")
	if err := other.Verify(tok, "i", "t", args{}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestRandomSecretPerProcess(t *testing.T) {
	a, _ := mgr(t, "")
	b, _ := mgr(t, "")
	tok, _, _ := a.Issue("i", "t", args{})
	if err := b.Verify(tok, "i", "t", args{}); err == nil {
		t.Fatal("random secrets must differ")
	}
}
