// Command api is the demo bank's payment screening API. The bank's Scam
// Weather node pushes decrypted signals to /v1/signals; the payment gateway
// calls /v1/payments/screen before money leaves.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/payments"
	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/screening"
	"github.com/iskander-kudashev-13/demo-bank-payments-api/internal/signals"
)

func main() {
	key := os.Getenv("GROUP_KEY")
	if key == "" {
		key = "demo-group-key"
	}
	eng := screening.New([]byte(key))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/signals", func(w http.ResponseWriter, r *http.Request) {
		var s signals.Signal
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]string{"signal_id": s.ID, "ack": eng.Apply(s)})
	})
	mux.HandleFunc("POST /v1/payments/screen", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p, err := payments.Parse(raw)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, eng.Screen(p))
	})
	mux.HandleFunc("GET /v1/signals/unsupported", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, eng.Unsupported())
	})
	addr := ":" + envOr("PORT", "8081")
	log.Printf("demo bank payments API on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
