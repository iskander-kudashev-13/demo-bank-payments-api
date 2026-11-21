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

func TestNormalizeDeviceID(t *testing.T) {
	const fp = "4b1d9e0c7a2f8e3d5c6b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d"
	for _, tc := range []struct{ in, want string }{
		{fp, fp},
		{"4B1D9E0C7A2F8E3D5C6B9A0F1E2D3C4B5A6F7E8D9C0B1A2F3E4D5C6B7A8F9E0D", fp},
		{"  " + fp + "\n", fp},
		{"4b1d9e0c-7a2f8e3d-5c6b9a0f-1e2d3c4b-5a6f7e8d-9c0b1a2f-3e4d5c6b-7a8f9e0d", fp},
		{"4B:1D:9E:0C:7A:2F:8E:3D:5C:6B:9A:0F:1E:2D:3C:4B:5A:6F:7E:8D:9C:0B:1A:2F:3E:4D:5C:6B:7A:8F:9E:0D", fp},
		{"4b1d 9e0c 7a2f 8e3d 5c6b 9a0f 1e2d 3c4b 5a6f 7e8d 9c0b 1a2f 3e4d 5c6b 7a8f 9e0d", fp},
		{"9F2C1E7A", "9f2c1e7a"},
	} {
		if got := NormalizeDeviceID(tc.in); got != tc.want {
			t.Errorf("NormalizeDeviceID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDeviceIndicator(t *testing.T) {
	key := []byte("demo-group-key")
	const fp = "4b1d9e0c7a2f8e3d5c6b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d"
	m := hmac.New(sha256.New, key)
	m.Write([]byte(fp))
	want := Indicator{Type: DeviceHMAC, Value: hex.EncodeToString(m.Sum(nil))}
	for _, in := range []string{fp, "4B1D9E0C7A2F8E3D5C6B9A0F1E2D3C4B5A6F7E8D9C0B1A2F3E4D5C6B7A8F9E0D", " " + fp + " "} {
		if got := DeviceIndicator(key, in); got != want {
			t.Errorf("DeviceIndicator(%q) = %+v, want %+v", in, got, want)
		}
	}
	if DeviceIndicator(key, "0000000000000000000000000000000000000000000000000000000000000000") == want {
		t.Error("different device must give a different indicator")
	}
	if DeviceIndicator([]byte("other-key"), fp) == want {
		t.Error("different group key must give a different indicator")
	}
}
