package circuitbreaker

import (
	"testing"

	"github.com/vyomite/dast/pkg/models"
)

func TestCircuitBreaker5xxTrip(t *testing.T) {
	cfg := models.ScanConfig{
		Consecutive5xxCap: 3,
		BaselineLatencyMs: 100,
		MaxRPS:            20,
	}

	cb := NewCircuitBreaker(cfg)

	// Initially healthy
	if !cb.CanExecute() {
		t.Fatalf("Circuit breaker should allow execution initially")
	}

	// 2 consecutive 5xx responses should NOT trip yet
	cb.RecordResponse(500, 100)
	cb.RecordResponse(502, 100)
	if !cb.CanExecute() {
		t.Fatalf("Circuit breaker should not trip before reaching cap")
	}

	// 3rd consecutive 5xx reaches threshold -> trips to OPEN
	cb.RecordResponse(503, 100)
	if cb.CanExecute() {
		t.Fatalf("Circuit breaker should trip to OPEN after 3 consecutive 5xx")
	}

	telemetry := cb.GetTelemetry()
	if telemetry.CurrentState != models.StateOpen {
		t.Errorf("Expected state OPEN, got %s", telemetry.CurrentState)
	}
	if telemetry.TripReason != models.ReasonConsecutive5xx {
		t.Errorf("Expected reason CONSECUTIVE_5XX_THRESHOLD_EXCEEDED, got %s", telemetry.TripReason)
	}
}

func TestCircuitBreakerDynamicLatencyBackoff(t *testing.T) {
	cfg := models.ScanConfig{
		Consecutive5xxCap: 5,
		BaselineLatencyMs: 100,
		LatencyBackoffCap: 300,
		MaxRPS:            20,
	}

	cb := NewCircuitBreaker(cfg)
	initialRPS := cb.GetCurrentRPS()

	// High latency responses trigger throttling (FR-4.4)
	for i := 0; i < 5; i++ {
		cb.RecordResponse(200, 900) // 900ms >> 300ms threshold
	}

	throttledRPS := cb.GetCurrentRPS()
	if throttledRPS >= initialRPS {
		t.Errorf("Expected throttled RPS to be lower than %f, got %f", initialRPS, throttledRPS)
	}

	telemetry := cb.GetTelemetry()
	if telemetry.CurrentState != models.StateThrottled {
		t.Errorf("Expected state THROTTLED, got %s", telemetry.CurrentState)
	}
}
