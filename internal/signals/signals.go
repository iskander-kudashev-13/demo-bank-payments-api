// Package signals holds the Scam Weather signal model as this bank's node
// sees it after the network layer has verified and decrypted a delivery.
package signals

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Indicator types defined by the network schema. This bank only knows how to
// compute AccountHMAC and WalletHMAC today; the others are received but cannot
// be matched.
const (
	AccountHMAC = "account_hmac" // HMAC of a normalised IBAN
	PhoneHMAC   = "phone_hmac"   // HMAC of an E.164 mobile number (Aani alias payments)
	WalletHMAC  = "wallet_hmac"  // HMAC of a crypto wallet address
	DeviceHMAC  = "device_hmac"  // HMAC of a mobile banking device fingerprint
)

type Indicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Signal is one warning from another bank.
type Signal struct {
	ID            string    `json:"signal_id"`
	Revision      int       `json:"revision"`
	Issuer        string    `json:"issuer"`
	Kind          string    `json:"kind"`
	Indicator     Indicator `json:"indicator"`
	EvidenceLevel string    `json:"evidence_level"` // issuer_analyst_verified | suspected
	ReasonCode    string    `json:"reason_code"`
	CaseCount     int       `json:"case_count"`
	ExpiresAt     time.Time `json:"expires_at"`
	Retracted     bool      `json:"retracted"`
}

// Active reports whether the signal may affect a payment at time now.
func (s Signal) Active(now time.Time) bool {
	return !s.Retracted && now.Before(s.ExpiresAt)
}

// NormalizeIBAN upper-cases an IBAN and strips spaces and dashes.
func NormalizeIBAN(iban string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(iban)))
}

// AccountIndicator is HMAC-SHA256(groupKey, normalised IBAN), hex encoded.
func AccountIndicator(groupKey []byte, iban string) Indicator {
	return Indicator{Type: AccountHMAC, Value: hmacHex(groupKey, NormalizeIBAN(iban))}
}

// NormalizeWallet lower-cases a crypto wallet address and removes all whitespace.
func NormalizeWallet(addr string) string {
	return strings.ToLower(strings.Join(strings.Fields(addr), ""))
}

// WalletIndicator is HMAC-SHA256(groupKey, normalised wallet address), hex encoded.
func WalletIndicator(groupKey []byte, addr string) Indicator {
	return Indicator{Type: WalletHMAC, Value: hmacHex(groupKey, NormalizeWallet(addr))}
}

func hmacHex(key []byte, s string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}
