package signals

import "testing"

func TestNormalizeWallet(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"already normal", "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c", "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"},
		{"mixed case", "0x5A1C9e0B7d3F2a4C6E8b0D1f3A5c7E9b1D3f5A7c", "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"},
		{"leading and trailing space", "  0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c\n", "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"},
		{"inner spaces", "0x5a1c 9e0b 7d3f 2a4c 6e8b 0d1f 3a5c 7e9b 1d3f 5a7c", "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"},
		{"tabs and newlines", "TDemo\tWallet\r\n0000\n1111", "tdemowallet00001111"},
		{"bech32 style", "BC1Q DEMO TEST WALLET 0000", "bc1qdemotestwallet0000"},
		{"dashes kept", "demo-wallet-01", "demo-wallet-01"},
		{"empty", "", ""},
		{"whitespace only", " \t\n ", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeWallet(tc.in); got != tc.want {
				t.Fatalf("NormalizeWallet(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestWalletIndicator(t *testing.T) {
	key := []byte("demo-group-key")
	a := WalletIndicator(key, "0x5A1C 9E0B 7D3F 2A4C 6E8B 0D1F 3A5C 7E9B 1D3F 5A7C")
	b := WalletIndicator(key, "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c")
	if a.Type != WalletHMAC || a != b {
		t.Fatalf("normalised forms must give the same indicator: %+v vs %+v", a, b)
	}
	if a.Value != hmacHex(key, "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c") {
		t.Fatalf("value is not HMAC of the normalised address: %s", a.Value)
	}
	if c := WalletIndicator(key, "0x0000000000000000000000000000000000000001"); c == a {
		t.Fatal("different wallets must give different indicators")
	}
	if d := WalletIndicator([]byte("other-group-key"), "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"); d == a {
		t.Fatal("different group keys must give different indicators")
	}
	if acct := AccountIndicator(key, "0x5a1c9e0b7d3f2a4c6e8b0d1f3a5c7e9b1d3f5a7c"); acct.Type == a.Type {
		t.Fatal("account and wallet indicators must have different types")
	}
}
