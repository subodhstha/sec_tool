package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// OOBHit records an out-of-band callback (FR-3.2)
type OOBHit struct {
	CorrelationID string    `json:"correlation_id"`
	Protocol      string    `json:"protocol"` // "HTTP" or "DNS"
	RemoteAddr    string    `json:"remote_addr"`
	Timestamp     time.Time `json:"timestamp"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Method        string    `json:"method,omitempty"`
}

type OOBServer struct {
	mu   sync.RWMutex
	hits map[string][]OOBHit
}

func NewOOBServer() *OOBServer {
	return &OOBServer{
		hits: make(map[string][]OOBHit),
	}
}

// RecordHit registers an incoming out-of-band callback
func (s *OOBServer) RecordHit(correlationID, protocol, remoteAddr, userAgent, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hit := OOBHit{
		CorrelationID: correlationID,
		Protocol:      protocol,
		RemoteAddr:    remoteAddr,
		Timestamp:     time.Now(),
		UserAgent:     userAgent,
		Method:        method,
	}

	s.hits[correlationID] = append(s.hits[correlationID], hit)
	log.Printf("[OOB Listener] HIT detected! ID: %s, Protocol: %s, From: %s", correlationID, protocol, remoteAddr)
}

// GetHits retrieves callbacks received for a correlation ID
func (s *OOBServer) GetHits(correlationID string) []OOBHit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hits[correlationID]
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	server := NewOOBServer()
	mux := http.NewServeMux()

	// 1. Incoming HTTP Callback endpoint (e.g., triggered by Blind SSRF)
	mux.HandleFunc("GET /callback/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		server.RecordHit(id, "HTTP", r.RemoteAddr, r.UserAgent(), r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Vyomite OOB Callback Acknowledged"))
	})
	mux.HandleFunc("POST /callback/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		server.RecordHit(id, "HTTP", r.RemoteAddr, r.UserAgent(), r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Vyomite OOB Callback Acknowledged"))
	})

	// 2. Verification API endpoint called by scanning workers to confirm blind vulnerabilities
	mux.HandleFunc("GET /api/v1/oob/verify/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		hits := server.GetHits(id)
		if len(hits) == 0 {
			http.Error(w, "no callbacks recorded for correlation id", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"correlation_id": id,
			"verified":       true,
			"hit_count":      len(hits),
			"hits":           hits,
		})
	})

	// 3. Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "vyomite-oob-listener",
			"version": "1.0.0",
		})
	})

	log.Printf("[Vyomite OOB Listener] Running on :%s (DNS & HTTP verification server)", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), mux); err != nil && err != http.ErrServerClosed {
		log.Fatalf("OOB Listener server error: %v", err)
	}
}
