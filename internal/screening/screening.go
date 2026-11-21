// Package screening checks outgoing payments against Scam Weather signals and
// applies this bank's policy. Decisions are deterministic and local: the
// network informs, the bank decides.
package screening

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/payments"
	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/signals"
)

// Policy maps a signal kind to the action for analyst-verified evidence.
// Suspected evidence never blocks, it only raises the risk score.
// Owned by the bank's Fraud Risk team; new kinds are proposed in a PR.
var Policy = map[string]string{
	"bec_beneficiary":      ActionReview,
	"app_scam_beneficiary": ActionReview,
	"mule_account":         ActionReview,
	"aani_proxy_scam":      ActionReview,
	"ato_device":           ActionReview,
}

// matchable is the set of indicator types this bank can compute from a payment.
var matchable = map[string]bool{
	signals.AccountHMAC: true,
	signals.PhoneHMAC:   true,
	signals.DeviceHMAC:  true,
}

const (
	ActionReview  = "REVIEW_REQUIRED"
	ActionApprove = "APPROVED"
)

// Decision is the result of screening one payment.
type Decision struct {
	PaymentID string   `json:"payment_id"`
	Decision  string   `json:"decision"`
	Reason    string   `json:"reason"`
	SignalID  string   `json:"signal_id,omitempty"`
	Unchecked []string `json:"unchecked_kinds,omitempty"` // active kinds we cannot match yet
}

// Engine stores signals and screens payments.
type Engine struct {
	mu       sync.Mutex
	groupKey []byte
	signals  map[string]signals.Signal
	now      func() time.Time
}

func New(groupKey []byte) *Engine {
	return &Engine{groupKey: groupKey, signals: map[string]signals.Signal{}, now: time.Now}
}

// Apply stores a signal revision. Older revisions are ignored and a
// retraction always wins. It returns the ack status for the network.
func (e *Engine) Apply(s signals.Signal) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, ok := e.signals[s.ID]
	if ok && (s.Revision <= cur.Revision || cur.Retracted) {
		return "obsolete"
	}
	if !s.Retracted && !e.now().Before(s.ExpiresAt) {
		return "expired"
	}
	e.signals[s.ID] = s
	return "applied"
}

// Supported reports whether this bank can match a signal kind to payments.
func Supported(s signals.Signal) bool {
	_, ok := Policy[s.Kind]
	return ok && matchable[s.Indicator.Type]
}

// indicators computes every indicator this bank can derive from a payment.
func (e *Engine) indicators(p payments.Payment) []signals.Indicator {
	var out []signals.Indicator
	if p.Creditor.IBAN != "" {
		out = append(out, signals.AccountIndicator(e.groupKey, p.Creditor.IBAN))
	}
	if p.Creditor.Proxy != nil && p.Creditor.Proxy.Mobile != "" {
		out = append(out, signals.PhoneIndicator(e.groupKey, p.Creditor.Proxy.Mobile))
	}
	if p.Channel.DeviceID != "" {
		out = append(out, signals.DeviceIndicator(e.groupKey, p.Channel.DeviceID))
	}
	return out
}

// Screen checks one payment.
func (e *Engine) Screen(p payments.Payment) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	d := Decision{PaymentID: p.ID, Decision: ActionApprove, Reason: "no active warning for this payee"}
	unchecked := map[string]bool{}
	inds := e.indicators(p)
	for _, s := range e.sorted() {
		if !s.Active(now) {
			continue
		}
		if !Supported(s) {
			unchecked[s.Kind] = true
			continue
		}
		if slices.Contains(inds, s.Indicator) && s.EvidenceLevel == "issuer_analyst_verified" {
			d.Decision, d.SignalID = Policy[s.Kind], s.ID
			subject := "payee"
			if s.Indicator.Type == signals.DeviceHMAC {
				subject = "payer's device"
			}
			d.Reason = fmt.Sprintf("%s reported this %s (%s, %s, %d related cases)", s.Issuer, subject, s.Kind, s.ReasonCode, s.CaseCount)
			return d
		}
	}
	for k := range unchecked {
		d.Unchecked = append(d.Unchecked, k)
	}
	sort.Strings(d.Unchecked)
	return d
}

// Unsupported lists active signals this bank stores but cannot match yet.
func (e *Engine) Unsupported() []signals.Signal {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []signals.Signal
	for _, s := range e.sorted() {
		if s.Active(e.now()) && !Supported(s) {
			out = append(out, s)
		}
	}
	return out
}

func (e *Engine) sorted() []signals.Signal {
	out := make([]signals.Signal, 0, len(e.signals))
	for _, s := range e.signals {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
