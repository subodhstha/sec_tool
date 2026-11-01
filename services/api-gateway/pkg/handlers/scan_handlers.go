package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/api-gateway/pkg/verification"
)

// ScanHandler provides HTTP API endpoints for scan management
type ScanHandler struct {
	store    models.ScanStore
	broker   models.Broker
	verifier *verification.DomainVerifier
}

func NewScanHandler(store models.ScanStore, broker models.Broker, verifier *verification.DomainVerifier) *ScanHandler {
	return &ScanHandler{
		store:    store,
		broker:   broker,
		verifier: verifier,
	}
}

// CreateScan handles POST /api/v1/scans
// Enforces FR-4.1 Domain Verification, creates scan job, pushes to queue, returns 202 Accepted
func (h *ScanHandler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req models.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	if req.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}
	if req.Config.PayloadProfile != "" {
		req.Config.PayloadProfile = strings.ToUpper(strings.TrimSpace(req.Config.PayloadProfile))
		if !isValidPayloadProfile(req.Config.PayloadProfile) {
			http.Error(w, "payload_profile must be one of PASSIVE, LIGHT, STANDARD, AGGRESSIVE, or FULL", http.StatusBadRequest)
			return
		}
	}

	// Default fallback config values
	if req.Config.MaxRPS <= 0 {
		req.Config.MaxRPS = 20
	}
	if req.Config.MaxConcurrency <= 0 {
		req.Config.MaxConcurrency = 10
	}
	if req.Config.MaxDepth <= 0 {
		req.Config.MaxDepth = 3
	}
	if req.Config.Consecutive5xxCap <= 0 {
		req.Config.Consecutive5xxCap = 5 // Circuit breaker triggers on 5 consecutive 5xx errors
	}
	if req.Config.BaselineLatencyMs <= 0 {
		req.Config.BaselineLatencyMs = 250 // Baseline 250ms
	}

	// FR-4.1: Domain Verification Safeguard
	verified, method, err := h.verifier.VerifyOwnership(r.Context(), req.TargetURL, req.Config.VerificationToken)
	if !verified || err != nil {
		details := "target ownership could not be verified"
		if err != nil {
			details = err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "FR-4.1 Domain Verification Failed: Target ownership could not be verified.",
			"details": details,
			"hint":    "Add TXT record or place token in /.well-known/vyomite-verification.txt, or use 'vyomite-dev-token' for local/staging bypass.",
		})
		return
	}

	scanID := uuid.New().String()
	job := &models.ScanJob{
		ID:        scanID,
		TargetURL: req.TargetURL,
		Status:    models.StatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Config:    req.Config,
		Auth:      req.Auth,
		Stats: models.ScanStats{
			TotalRequestsSent:    0,
			CurrentRPS:           0,
			AverageLatencyMs:     req.Config.BaselineLatencyMs,
			Consecutive5xxCount:  0,
			CircuitBreakerTrips:  0,
			EndpointsDiscovered:  0,
			EndpointsScanned:     0,
			VulnerabilitiesFound: 0,
		},
	}

	// Persist initial state
	if err := h.store.SaveScan(job); err != nil {
		http.Error(w, fmt.Sprintf("failed to save scan: %v", err), http.StatusInternalServerError)
		return
	}

	// Enqueue to broker for worker consumption
	if err := h.broker.PublishScanJob(r.Context(), job); err != nil {
		http.Error(w, fmt.Sprintf("failed to enqueue scan job: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted) // 202 Accepted as required by SRS
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":             scanID,
		"status":              models.StatusPending,
		"message":             "Scan accepted and queued for worker execution",
		"verification_method": method,
		"target_url":          req.TargetURL,
		"safe_mode":           req.Config.SafeMode,
	})
}

func isValidPayloadProfile(profile string) bool {
	switch profile {
	case "PASSIVE", "LIGHT", "STANDARD", "AGGRESSIVE", "FULL":
		return true
	default:
		return false
	}
}

// GetScan handles GET /api/v1/scans/{id}
func (h *ScanHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.store.GetScan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

// ListScans handles GET /api/v1/scans
func (h *ScanHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	scans := h.store.ListScans()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scans": scans,
		"total": len(scans),
	})
}

// AbortScan handles POST /api/v1/scans/{id}/abort (Incident Response Scenario A/C)
func (h *ScanHandler) AbortScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	_, err := h.store.GetScan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update status and broadcast abort signal
	_ = h.store.UpdateScanStatus(id, models.StatusAborted)
	_ = h.broker.PublishAbortSignal(r.Context(), id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": id,
		"status":  models.StatusAborted,
		"message": "Abort signal dispatched to scanning workers.",
	})
}

// GetResults handles GET /api/v1/scans/{id}/results
// Supports ?format=sarif for developer-native CI/CD integration (FR-5.2)
func (h *ScanHandler) GetResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.store.GetScan(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	findings := h.store.GetFindingsByScanID(id)

	format := r.URL.Query().Get("format")
	if format == "sarif" {
		sarifReport := models.GenerateSARIFReport(scan.ID, scan.TargetURL, findings)
		w.Header().Set("Content-Type", "application/sarif+json")
		json.NewEncoder(w).Encode(sarifReport)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":     id,
		"target_url":  scan.TargetURL,
		"status":      scan.Status,
		"total_count": len(findings),
		"findings":    findings,
	})
}
