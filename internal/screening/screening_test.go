package screening

import (
	"testing"
	"time"

	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/payments"
	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/signals"
)

var key = []byte("demo-group-key")

func engineAt(t time.Time) *Engine {
	e := New(key)
	e.now = func() time.Time { return t }
	return e
}

func ibanPayment(iban string) payments.Payment {
	return payments.Payment{ID: "pay-1", Rail: "UAEFTS", Creditor: payments.Creditor{Name: "Supplier", IBAN: iban},
		Amount: payments.Amount{Value: "450000.00", Currency: "AED"}}
}

func signal(id string, ind signals.Indicator, kind string, exp time.Time) signals.Signal {
	return signals.Signal{ID: id, Revision: 1, Issuer: "Bank A", Kind: kind, Indicator: ind,
		EvidenceLevel: "issuer_analyst_verified", ReasonCode: "confirmed_bec_case", CaseCount: 3, ExpiresAt: exp}
}

func TestMatchingIBANIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(signal("sig-1", signals.AccountIndicator(key, "AE07 0331 2345 6789 0123 456"), "bec_beneficiary", now.Add(time.Hour)))
	d := e.Screen(ibanPayment("ae07-0331-2345-6789-0123-456"))
	if d.Decision != ActionReview || d.SignalID != "sig-1" {
		t.Fatalf("want review on sig-1, got %+v", d)
	}
}

func TestOtherIBANIsApproved(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(signal("sig-1", signals.AccountIndicator(key, "AE070331234567890123456"), "bec_beneficiary", now.Add(time.Hour)))
	if d := e.Screen(ibanPayment("AE460260001234567890101")); d.Decision != ActionApprove {
		t.Fatalf("want approve, got %+v", d)
	}
}

func TestRetractionWinsAndOldRevisionIgnored(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := signal("sig-1", signals.AccountIndicator(key, "AE070331234567890123456"), "bec_beneficiary", now.Add(time.Hour))
	e.Apply(s)
	r := s
	r.Revision, r.Retracted = 2, true
	if got := e.Apply(r); got != "applied" {
		t.Fatalf("retract: %s", got)
	}
	if got := e.Apply(s); got != "obsolete" {
		t.Fatalf("old revision after retract: %s", got)
	}
	if d := e.Screen(ibanPayment("AE070331234567890123456")); d.Decision != ActionApprove {
		t.Fatalf("retracted signal must not hold: %+v", d)
	}
}

func TestExpiredSignalNotApplied(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	if got := e.Apply(signal("sig-1", signals.AccountIndicator(key, "AE070331234567890123456"), "bec_beneficiary", now.Add(-time.Minute))); got != "expired" {
		t.Fatalf("want expired, got %s", got)
	}
}

func TestUnsupportedKindsAreReported(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(signal("sig-9", signals.Indicator{Type: signals.PhoneHMAC, Value: "abc"}, "aani_proxy_scam", now.Add(time.Hour)))
	p := payments.Payment{ID: "pay-2", Rail: "AANI", Creditor: payments.Creditor{Name: "Payee", Proxy: &payments.Proxy{Mobile: "+971501234567"}},
		Amount: payments.Amount{Value: "9000", Currency: "AED"}}
	d := e.Screen(p)
	if d.Decision != ActionApprove || len(d.Unchecked) != 1 || d.Unchecked[0] != "aani_proxy_scam" {
		t.Fatalf("want approve with aani_proxy_scam unchecked, got %+v", d)
	}
	if n := len(e.Unsupported()); n != 1 {
		t.Fatalf("want 1 unsupported signal, got %d", n)
	}
}
