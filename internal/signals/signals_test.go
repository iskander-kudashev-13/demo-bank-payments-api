package signals

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestNormalizeUAEMobile(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"+971501234567", "+971501234567"},
		{"+971 50 123 4567", "+971501234567"},
		{"00971501234567", "+971501234567"},
		{"00 971 50 123 4567", "+971501234567"},
		{"0501234567", "+971501234567"},
		{"050 123 4567", "+971501234567"},
		{"050-123-4567", "+971501234567"},
		{"  0551234567 ", "+971551234567"},
		{"+971 58 765 4321", "+971587654321"},
	} {
		if got := NormalizeUAEMobile(tc.in); got != tc.want {
			t.Errorf("NormalizeUAEMobile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPhoneIndicator(t *testing.T) {
	key := []byte("demo-group-key")
	m := hmac.New(sha256.New, key)
	m.Write([]byte("+971501234567"))
	want := Indicator{Type: PhoneHMAC, Value: hex.EncodeToString(m.Sum(nil))}
	for _, in := range []string{"+971501234567", "00971501234567", "050 123 4567"} {
		if got := PhoneIndicator(key, in); got != want {
			t.Errorf("PhoneIndicator(%q) = %+v, want %+v", in, got, want)
		}
	}
	if PhoneIndicator(key, "0509999999") == want {
		t.Error("different number must give a different indicator")
	}
	if PhoneIndicator([]byte("other-key"), "+971501234567") == want {
		t.Error("different group key must give a different indicator")
	}
}
