package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/api-gateway/pkg/handlers"
	"github.com/vyomite/dast/services/api-gateway/pkg/verification"
)

// withCORS adds permissive headers for API clients and local frontend dashboard
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	allowLocalDev := os.Getenv("ENV") != "production"

	// 1. Initialize Core Services
	store := models.GetMemoryStore()
	broker := models.GetMemoryBroker()
	verifier := verification.NewDomainVerifier(allowLocalDev)

	// 2. Initialize Handlers
	scanHandler := handlers.NewScanHandler(store, broker, verifier)

	// 3. Register HTTP Routes using Go 1.22+ ServeMux
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/scans", scanHandler.CreateScan)
	mux.HandleFunc("GET /api/v1/scans", scanHandler.ListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", scanHandler.GetScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/abort", scanHandler.AbortScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/results", scanHandler.GetResults)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "vyomite-api-gateway",
			"version": "1.0.0",
		})
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: withCORS(mux),
	}

	log.Printf("[Vyomite API Gateway] Listening on :%s (local verification bypass: %v)", port, allowLocalDev)
	
	// Start the embedded scan worker so it shares the memory queue
	go StartWorker()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}
