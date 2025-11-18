// supervisor-sidecar/main.go
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	log.Println("FrostGate supervisor-sidecar starting...")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","component":"supervisor-sidecar"}`))
	})

	addr := ":9090"
	if v := os.Getenv("SUPERVISOR_PORT"); v != "" {
		addr = ":" + v
	}

	log.Printf("Listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("supervisor-sidecar failed: %v", err)
	}
}
