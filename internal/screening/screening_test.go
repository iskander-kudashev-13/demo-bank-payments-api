package screening

import (
	"os"
	"strings"
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
	e.Apply(signal("sig-9", signals.Indicator{Type: signals.WalletHMAC, Value: "abc"}, "crypto_offramp_wallet", now.Add(time.Hour)))
	p := payments.Payment{ID: "pay-2", Rail: "VASP", Creditor: payments.Creditor{Name: "Payee", VASP: &payments.VASP{Name: "Exchange", Wallet: "bc1qsynthetic"}},
		Amount: payments.Amount{Value: "9000", Currency: "AED"}}
	d := e.Screen(p)
	if d.Decision != ActionApprove || len(d.Unchecked) != 1 || d.Unchecked[0] != "crypto_offramp_wallet" {
		t.Fatalf("want approve with crypto_offramp_wallet unchecked, got %+v", d)
	}
	if n := len(e.Unsupported()); n != 1 {
		t.Fatalf("want 1 unsupported signal, got %d", n)
	}
}

func aaniPayment(mobile string) payments.Payment {
	return payments.Payment{ID: "pay-aani", Rail: "AANI", Creditor: payments.Creditor{Name: "Payee", Proxy: &payments.Proxy{Mobile: mobile}},
		Amount: payments.Amount{Value: "9500", Currency: "AED"}}
}

func aaniSignal(id, mobile string, exp time.Time) signals.Signal {
	s := signal(id, signals.PhoneIndicator(key, mobile), "aani_proxy_scam", exp)
	s.ReasonCode = "confirmed_scam_payee"
	return s
}

func TestMatchingAaniMobileIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	for _, mobile := range []string{"+971501234567", "00971501234567", "050 123 4567"} {
		d := e.Screen(aaniPayment(mobile))
		if d.Decision != ActionReview || d.SignalID != "sig-aani" || len(d.Unchecked) != 0 {
			t.Fatalf("%s: want review on sig-aani, got %+v", mobile, d)
		}
	}
}

func TestAaniFixtureIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	raw, err := os.ReadFile("../../testdata/aani.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := payments.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d := e.Screen(p); d.Decision != ActionReview || d.SignalID != "sig-aani" {
		t.Fatalf("want review on sig-aani, got %+v", d)
	}
}

func TestOtherAaniMobileIsApproved(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	d := e.Screen(aaniPayment("+971559876543"))
	if d.Decision != ActionApprove || d.SignalID != "" || len(d.Unchecked) != 0 {
		t.Fatalf("want approve with nothing unchecked, got %+v", d)
	}
}

func TestAaniSignalDoesNotMatchIBAN(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	if d := e.Screen(ibanPayment("AE070331234567890123456")); d.Decision != ActionApprove {
		t.Fatalf("want approve, got %+v", d)
	}
}

func TestSuspectedAaniSignalDoesNotHold(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour))
	s.EvidenceLevel = "suspected"
	e.Apply(s)
	if d := e.Screen(aaniPayment("+971501234567")); d.Decision != ActionApprove {
		t.Fatalf("suspected evidence must not hold: %+v", d)
	}
}

func TestRetractedAaniSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour))
	e.Apply(s)
	r := s
	r.Revision, r.Retracted = 2, true
	if got := e.Apply(r); got != "applied" {
		t.Fatalf("retract: %s", got)
	}
	d := e.Screen(aaniPayment("+971501234567"))
	if d.Decision != ActionApprove || len(d.Unchecked) != 0 {
		t.Fatalf("retracted signal must not hold: %+v", d)
	}
}

func TestExpiredAaniSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	if got := e.Apply(aaniSignal("sig-old", "+971501234567", now.Add(-time.Minute))); got != "expired" {
		t.Fatalf("want expired, got %s", got)
	}
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	e.now = func() time.Time { return now.Add(2 * time.Hour) }
	d := e.Screen(aaniPayment("+971501234567"))
	if d.Decision != ActionApprove || len(d.Unchecked) != 0 {
		t.Fatalf("expired signal must not hold: %+v", d)
	}
}

func TestAaniKindNoLongerUnchecked(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour)))
	e.Apply(signal("sig-wal", signals.Indicator{Type: signals.WalletHMAC, Value: "abc"}, "crypto_offramp_wallet", now.Add(time.Hour)))
	for _, p := range []payments.Payment{aaniPayment("+971559876543"), ibanPayment("AE460260001234567890101")} {
		d := e.Screen(p)
		if d.Decision != ActionApprove || len(d.Unchecked) != 1 || d.Unchecked[0] != "crypto_offramp_wallet" {
			t.Fatalf("want approve with only crypto_offramp_wallet unchecked, got %+v", d)
		}
	}
	if !Supported(aaniSignal("sig-aani", "+971501234567", now.Add(time.Hour))) {
		t.Fatal("aani_proxy_scam with phone_hmac must be supported")
	}
	for _, s := range e.Unsupported() {
		if s.Kind == "aani_proxy_scam" {
			t.Fatalf("aani_proxy_scam still reported unsupported: %+v", s)
		}
	}
}

const (
	atoDevice   = "4b1d9e0c7a2f8e3d5c6b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d"
	otherDevice = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
)

func devicePayment(deviceID string) payments.Payment {
	p := ibanPayment("AE460260001234567890101")
	p.ID = "pay-mobile"
	p.Channel = payments.Channel{DeviceID: deviceID}
	return p
}

func atoSignal(id, deviceID string, exp time.Time) signals.Signal {
	s := signal(id, signals.DeviceIndicator(key, deviceID), "ato_device", exp)
	s.Issuer, s.ReasonCode = "FAB", "confirmed_account_takeover"
	return s
}

func TestMatchingATODeviceIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(atoSignal("sig-ato", atoDevice, now.Add(time.Hour)))
	for _, id := range []string{atoDevice, strings.ToUpper(atoDevice), " " + atoDevice + " "} {
		d := e.Screen(devicePayment(id))
		if d.Decision != ActionReview || d.SignalID != "sig-ato" || len(d.Unchecked) != 0 {
			t.Fatalf("%s: want review on sig-ato, got %+v", id, d)
		}
		if !strings.Contains(d.Reason, "device") {
			t.Fatalf("reason should name the device: %q", d.Reason)
		}
	}
}

func TestATODeviceFixtureIsHeld(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	raw, err := os.ReadFile("../../testdata/aani.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := payments.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.Apply(atoSignal("sig-ato", p.Channel.DeviceID, now.Add(time.Hour)))
	if d := e.Screen(p); d.Decision != ActionReview || d.SignalID != "sig-ato" {
		t.Fatalf("want review on sig-ato, got %+v", d)
	}
}

func TestOtherATODeviceIsApproved(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(atoSignal("sig-ato", atoDevice, now.Add(time.Hour)))
	for _, p := range []payments.Payment{devicePayment(otherDevice), devicePayment(""), ibanPayment("AE460260001234567890101")} {
		d := e.Screen(p)
		if d.Decision != ActionApprove || d.SignalID != "" || len(d.Unchecked) != 0 {
			t.Fatalf("device %q: want approve with nothing unchecked, got %+v", p.Channel.DeviceID, d)
		}
	}
}

func TestATODeviceSignalDoesNotMatchPayeeIndicators(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(atoSignal("sig-ato", atoDevice, now.Add(time.Hour)))
	for _, p := range []payments.Payment{ibanPayment(atoDevice), aaniPayment(atoDevice)} {
		if d := e.Screen(p); d.Decision != ActionApprove {
			t.Fatalf("device signal must only match channel.device_id, got %+v", d)
		}
	}
}

func TestSuspectedATODeviceSignalDoesNotHold(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := atoSignal("sig-ato", atoDevice, now.Add(time.Hour))
	s.EvidenceLevel = "suspected"
	e.Apply(s)
	if d := e.Screen(devicePayment(atoDevice)); d.Decision != ActionApprove {
		t.Fatalf("suspected evidence must not hold: %+v", d)
	}
}

func TestRetractedATODeviceSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	s := atoSignal("sig-ato", atoDevice, now.Add(time.Hour))
	e.Apply(s)
	r := s
	r.Revision, r.Retracted = 2, true
	if got := e.Apply(r); got != "applied" {
		t.Fatalf("retract: %s", got)
	}
	if got := e.Apply(s); got != "obsolete" {
		t.Fatalf("old revision after retract: %s", got)
	}
	d := e.Screen(devicePayment(atoDevice))
	if d.Decision != ActionApprove || len(d.Unchecked) != 0 {
		t.Fatalf("retracted signal must not hold: %+v", d)
	}
}

func TestExpiredATODeviceSignalHasNoEffect(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	if got := e.Apply(atoSignal("sig-old", atoDevice, now.Add(-time.Minute))); got != "expired" {
		t.Fatalf("want expired, got %s", got)
	}
	e.Apply(atoSignal("sig-ato", atoDevice, now.Add(time.Hour)))
	e.now = func() time.Time { return now.Add(2 * time.Hour) }
	d := e.Screen(devicePayment(atoDevice))
	if d.Decision != ActionApprove || len(d.Unchecked) != 0 {
		t.Fatalf("expired signal must not hold: %+v", d)
	}
}

func TestATODeviceKindNoLongerUnchecked(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	e := engineAt(now)
	e.Apply(atoSignal("sig-ato", atoDevice, now.Add(time.Hour)))
	e.Apply(signal("sig-wal", signals.Indicator{Type: signals.WalletHMAC, Value: "abc"}, "crypto_offramp_wallet", now.Add(time.Hour)))
	for _, p := range []payments.Payment{devicePayment(otherDevice), ibanPayment("AE460260001234567890101"), aaniPayment("+971559876543")} {
		d := e.Screen(p)
		if d.Decision != ActionApprove || len(d.Unchecked) != 1 || d.Unchecked[0] != "crypto_offramp_wallet" {
			t.Fatalf("want approve with only crypto_offramp_wallet unchecked, got %+v", d)
		}
	}
	if !Supported(atoSignal("sig-ato", atoDevice, now.Add(time.Hour))) {
		t.Fatal("ato_device with device_hmac must be supported")
	}
	for _, s := range e.Unsupported() {
		if s.Kind == "ato_device" {
			t.Fatalf("ato_device still reported unsupported: %+v", s)
		}
	}
}
