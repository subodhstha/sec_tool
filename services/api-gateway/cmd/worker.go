package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/fuzzer"
)

// CrawlerClient calls the headless Node.js/TypeScript crawler microservice (FR-1.1, FR-1.2, FR-1.3)
type CrawlerClient struct {
	crawlerURL string
	httpClient *http.Client
}

func NewCrawlerClient(crawlerURL string) *CrawlerClient {
	return &CrawlerClient{
		crawlerURL: crawlerURL,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// DiscoverEndpoints queries the crawler service or falls back to root endpoint discovery
func (c *CrawlerClient) DiscoverEndpoints(ctx context.Context, targetURL string, maxDepth int) ([]models.TargetEndpoint, error) {
	if c.crawlerURL != "" {
		reqBody, _ := json.Marshal(map[string]interface{}{
			"target_url": targetURL,
			"max_depth":  maxDepth,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/crawl", c.crawlerURL), bytes.NewBuffer(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				var endpoints []models.TargetEndpoint
				if err := json.NewDecoder(resp.Body).Decode(&endpoints); err == nil {
					return endpoints, nil
				}
			}
		}
	}

	// Fallback: Default seed discovery for the root URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	endpoints := []models.TargetEndpoint{
		{
			URL:        targetURL,
			Normalized: parsed.Path,
			Method:     "GET",
			Source:     "SEED",
			Parameters: []models.EndpointParam{
				{Name: "id", Location: "query", Value: "1"},
				{Name: "search", Location: "query", Value: "test"},
			},
		},
		{
			URL:        fmt.Sprintf("%s://%s/api/v1/profile", parsed.Scheme, parsed.Host),
			Normalized: "/api/v1/profile",
			Method:     "GET",
			Source:     "SEED",
			Parameters: []models.EndpointParam{
				{Name: "user_id", Location: "query", Value: "42"},
			},
		},
	}
	return endpoints, nil
}

func processScanJob(
	ctx context.Context,
	job *models.ScanJob,
	store models.ScanStore,
	crawler *CrawlerClient,
	oobURL string,
	abortChan <-chan string,
) {
	log.Printf("[Worker] Starting scan %s for target: %s (SafeMode=%v, ActiveFuzzing=%v)",
		job.ID, job.TargetURL, job.Config.SafeMode, job.Config.ActiveFuzzing)

	_ = store.UpdateScanStatus(job.ID, models.StatusRunning)

	engine := fuzzer.NewAttackSimulationEngine(job.Config, job.Auth, oobURL)

	// Step 1: Passive Fingerprinting & Sensitive Metadata Exposure (FR-3.1 & Pentest Checklist)
	fp := engine.FingerprintTarget(ctx, job.TargetURL)
	job.Fingerprint = fp
	log.Printf("[Worker] Target %s fingerprinted: Server=%s, Frameworks=%v, Languages=%v",
		job.TargetURL, fp.ServerHeader, fp.Frameworks, fp.Languages)

	// Probe sensitive files (.git, .env, robots.txt, phpinfo.php)
	fileFindings := engine.ProbeSensitiveFiles(ctx, job.ID, job.TargetURL)
	job.Stats.VulnerabilitiesFound += len(fileFindings)
	for _, f := range fileFindings {
		_ = store.AddFinding(&f)
	}

	// Step 2: Crawling & Discovery (FR-1.1, FR-1.3)
	endpoints, err := crawler.DiscoverEndpoints(ctx, job.TargetURL, job.Config.MaxDepth)
	if err != nil {
		log.Printf("[Worker] Crawl error for %s: %v", job.TargetURL, err)
	}
	job.Stats.EndpointsDiscovered = len(endpoints)
	_ = store.UpdateScanStats(job.ID, job.Stats)

	// Step 3: Fuzzing Loop
	aborted := false
	for i, ep := range endpoints {
		// Check abort signal
		select {
		case abortID := <-abortChan:
			if abortID == job.ID || abortID == "ALL" {
				log.Printf("[Worker] Abort received for scan %s. Stopping execution.", job.ID)
				aborted = true
				break
			}
		case <-ctx.Done():
			aborted = true
			break
		default:
		}

		if aborted {
			break
		}

		// Execute attack simulation on endpoint
		findings, scanErr := engine.ScanEndpoint(ctx, job.ID, ep, fp, job.Config.ActiveFuzzing)
		if scanErr != nil {
			if strings.Contains(scanErr.Error(), "circuit breaker") {
				log.Printf("[Worker] Circuit Breaker Tripped on scan %s: %v", job.ID, scanErr)
				_ = store.UpdateScanStatus(job.ID, models.StatusPausedCircuitBreaker)
			}
		}

		for _, f := range findings {
			_ = store.AddFinding(&f)
		}
		job.Stats.VulnerabilitiesFound += len(findings)

		job.Stats.EndpointsScanned = i + 1
		job.Stats.TotalRequestsSent = engine.GetTotalRequests()
		cbTelemetry := engine.GetCircuitBreaker().GetTelemetry()
		job.Stats.CircuitBreakerTrips = cbTelemetry.TotalTripsCount
		job.Stats.Consecutive5xxCount = cbTelemetry.Consecutive5xxCount
		job.Stats.AverageLatencyMs = cbTelemetry.MovingAvgLatencyMs
		job.Stats.CurrentRPS = cbTelemetry.CurrentRPS
		_ = store.UpdateScanStats(job.ID, job.Stats)
	}

	if aborted {
		_ = store.UpdateScanStatus(job.ID, models.StatusAborted)
		log.Printf("[Worker] Scan %s terminated as ABORTED", job.ID)
	} else {
		_ = store.UpdateScanStatus(job.ID, models.StatusCompleted)
		log.Printf("[Worker] Scan %s COMPLETED successfully. Endpoints scanned: %d, Vulns: %d",
			job.ID, job.Stats.EndpointsScanned, job.Stats.VulnerabilitiesFound)
	}
}

func StartWorker() {
	crawlerURL := os.Getenv("CRAWLER_SERVICE_URL")
	if crawlerURL == "" {
		crawlerURL = "http://localhost:3001"
	}

	oobURL := os.Getenv("OOB_LISTENER_URL")
	if oobURL == "" {
		oobURL = "http://localhost:8082"
	}

	store := models.GetMemoryStore()
	broker := models.GetMemoryBroker()
	crawler := NewCrawlerClient(crawlerURL)

	jobChan, err := broker.SubscribeScanJobs()
	if err != nil {
		log.Fatalf("Failed to subscribe to scan jobs: %v", err)
	}

	abortChan, err := broker.SubscribeAbortSignals()
	if err != nil {
		log.Fatalf("Failed to subscribe to abort signals: %v", err)
	}

	ctx := context.Background()

	log.Printf("[Vyomite Scan Worker] Running inside API Gateway and listening for scan jobs on queue...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[Worker] Worker exited.")
			return
		case job, ok := <-jobChan:
			if !ok {
				return
			}
			processScanJob(ctx, job, store, crawler, oobURL, abortChan)
		}
	}
}
