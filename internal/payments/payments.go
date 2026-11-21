// Package payments is the bank's outgoing payment format and its parser.
package payments

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Payment is an outgoing customer payment as the core banking system sends it.
type Payment struct {
	ID       string   `json:"txn_ref"`
	Rail     string   `json:"rail"` // UAEFTS | AANI | VASP
	Creditor Creditor `json:"creditor"`
	Amount   Amount   `json:"amt"`
	Channel  Channel  `json:"channel"`
}

type Creditor struct {
	Name  string `json:"name"`
	IBAN  string `json:"iban,omitempty"`
	Proxy *Proxy `json:"proxy,omitempty"` // Aani alias payments
	VASP  *VASP  `json:"vasp,omitempty"`  // transfers to a licensed crypto exchange
}

type Proxy struct {
	Mobile string `json:"mobile"`
}

type VASP struct {
	Name   string `json:"name"`
	Wallet string `json:"wallet"`
}

type Amount struct {
	Value    string `json:"value"`
	Currency string `json:"ccy"`
}

type Channel struct {
	DeviceID string `json:"device_id,omitempty"`
}

// Parse decodes and validates a payment.
func Parse(raw []byte) (Payment, error) {
	var p Payment
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("decode payment: %w", err)
	}
	if p.ID == "" {
		return p, fmt.Errorf("missing txn_ref")
	}
	if p.Creditor.IBAN == "" && p.Creditor.Proxy == nil && p.Creditor.VASP == nil {
		return p, fmt.Errorf("%s: creditor has no iban, proxy or vasp", p.ID)
	}
	if _, err := p.AmountMinor(); err != nil {
		return p, err
	}
	p.Amount.Currency = strings.ToUpper(p.Amount.Currency)
	return p, nil
}

// AmountMinor returns the amount in minor units (fils).
func (p Payment) AmountMinor() (int64, error) {
	v := strings.TrimSpace(p.Amount.Value)
	if v == "" {
		return 0, fmt.Errorf("%s: missing amount", p.ID)
	}
	whole, frac, _ := strings.Cut(v, ".")
	frac = (frac + "00")[:2]
	n, err := strconv.ParseInt(whole+frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: bad amount %q", p.ID, v)
	}
	return n, nil
}
