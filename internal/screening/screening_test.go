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

const (
	demoWallet  = "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"
	otherWallet = "0x0000000000000000000000000000000000000001"
)

func vaspPayment(wallet string) payments.Payment {
	return payments.Payment{ID: "pay-3", Rail: "VASP",
		Creditor: payments.Creditor{Name: "Payee", VASP: &payments.VASP{Name: "Demo Exchange", Wallet: wallet}},
		Amount:   payments.Amount{Value: "25000", Currency: "AED"}}
}

func walletSignal(id, wallet string, exp time.Time) signals.Signal {
	s := signal(id, signals.WalletIndicator(key, wallet), "crypto_offramp_wallet", exp)
	s.Issuer, s.ReasonCode = "Bank C", "confirmed_scam_cashout"
	return s
}

func TestMatchingWalletIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(walletSignal("sig-w1", demoWallet, now.Add(time.Hour)))
	d := e.Screen(vaspPayment("  0x5A1C 9E0B 7D3F 2A4C 6E8B 0D1F 3A5C 7E9B 1D3F 5A7C "))
	if d.Decision != ActionReview || d.SignalID != "sig-w1" || len(d.Unchecked) != 0 {
		t.Fatalf("want review on sig-w1, got %+v", d)
	}
}

func TestOtherWalletIsApproved(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(walletSignal("sig-w1", demoWallet, now.Add(time.Hour)))
	if d := e.Screen(vaspPayment(otherWallet)); d.Decision != ActionApprove || d.SignalID != "" {
		t.Fatalf("want approve, got %+v", d)
	}
}

func TestSuspectedWalletSignalDoesNotHold(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := walletSignal("sig-w1", demoWallet, now.Add(time.Hour))
	s.EvidenceLevel = "suspected"
	e.Apply(s)
	if d := e.Screen(vaspPayment(demoWallet)); d.Decision != ActionApprove {
		t.Fatalf("suspected evidence must not hold: %+v", d)
	}
}

func TestRetractedWalletSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := walletSignal("sig-w1", demoWallet, now.Add(time.Hour))
	e.Apply(s)
	r := s
	r.Revision, r.Retracted = 2, true
	if got := e.Apply(r); got != "applied" {
		t.Fatalf("retract: %s", got)
	}
	if got := e.Apply(s); got != "obsolete" {
		t.Fatalf("old revision after retract: %s", got)
	}
	if d := e.Screen(vaspPayment(demoWallet)); d.Decision != ActionApprove || len(d.Unchecked) != 0 {
		t.Fatalf("retracted signal must not hold: %+v", d)
	}
}

func TestExpiredWalletSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	if got := e.Apply(walletSignal("sig-w1", demoWallet, now.Add(-time.Minute))); got != "expired" {
		t.Fatalf("want expired, got %s", got)
	}
	if d := e.Screen(vaspPayment(demoWallet)); d.Decision != ActionApprove {
		t.Fatalf("expired signal must not hold: %+v", d)
	}

	// A signal that was active when applied stops holding once it expires.
	e.Apply(walletSignal("sig-w2", demoWallet, now.Add(time.Hour)))
	e.now = func() time.Time { return now.Add(2 * time.Hour) }
	if d := e.Screen(vaspPayment(demoWallet)); d.Decision != ActionApprove {
		t.Fatalf("signal past expiry must not hold: %+v", d)
	}
}

func TestWalletKindNoLongerUnchecked(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(walletSignal("sig-w1", demoWallet, now.Add(time.Hour)))
	e.Apply(signal("sig-9", signals.Indicator{Type: signals.PhoneHMAC, Value: "abc"}, "aani_proxy_scam", now.Add(time.Hour)))
	for _, p := range []payments.Payment{vaspPayment(otherWallet), ibanPayment("AE460260001234567890101")} {
		d := e.Screen(p)
		if d.Decision != ActionApprove || len(d.Unchecked) != 1 || d.Unchecked[0] != "aani_proxy_scam" {
			t.Fatalf("want approve with only aani_proxy_scam unchecked, got %+v", d)
		}
	}
	un := e.Unsupported()
	if len(un) != 1 || un[0].Kind != "aani_proxy_scam" {
		t.Fatalf("want only aani_proxy_scam unsupported, got %+v", un)
	}
	if !Supported(walletSignal("sig-w1", demoWallet, now.Add(time.Hour))) {
		t.Fatal("crypto_offramp_wallet with wallet_hmac must be supported")
	}
}
