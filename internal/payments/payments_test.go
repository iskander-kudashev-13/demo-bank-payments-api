package payments

import (
	"os"
	"testing"
)

func TestParseFixtures(t *testing.T) {
	for _, f := range []string{"iban.json", "aani.json"} {
		raw, err := os.ReadFile("../../testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if n, _ := p.AmountMinor(); n <= 0 {
			t.Fatalf("%s: amount %d", f, n)
		}
	}
}

func TestParseRejectsMissingCreditor(t *testing.T) {
	if _, err := Parse([]byte(`{"txn_ref":"x","amt":{"value":"1","ccy":"AED"},"creditor":{"name":"n"}}`)); err == nil {
		t.Fatal("want error")
	}
}

func TestAmountWithoutDecimals(t *testing.T) {
	p := Payment{ID: "x", Amount: Amount{Value: "450000"}}
	if n, err := p.AmountMinor(); err != nil || n != 45000000 {
		t.Fatalf("got %d %v", n, err)
	}
}
