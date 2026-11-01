package circuitbreaker

import (
	"sync"
	"time"

	"github.com/vyomite/dast/pkg/models"
)

// CircuitBreaker manages active safety, 5xx trip detection, and dynamic latency back-off (FR-4.3, FR-4.4)
type CircuitBreaker struct {
	mu                  sync.RWMutex
	state               models.CBState
	tripReason          models.TripReason
	consecutive5xx      int
	consecutive5xxCap   int
	baselineLatencyMs   int64
	movingAvgLatencyMs  int64
	latencyThresholdMs  int64
	currentRPS          float64
	configuredMaxRPS    int
	totalTrips          int
	lastStateChange     time.Time
	cooldownDuration    time.Duration
	cooldownEndsAt      time.Time
	successProbeCount   int
}

// NewCircuitBreaker creates a circuit breaker instance for a scan target
func NewCircuitBreaker(cfg models.ScanConfig) *CircuitBreaker {
	baseline := cfg.BaselineLatencyMs
	if baseline <= 0 {
		baseline = 250 // Default baseline 250ms
	}

	fiveXxCap := cfg.Consecutive5xxCap
	if fiveXxCap <= 0 {
		fiveXxCap = 5 // Trigger after 5 consecutive 5xx
	}

	maxRPS := cfg.MaxRPS
	if maxRPS <= 0 {
		maxRPS = 20
	}

	threshold := cfg.LatencyBackoffCap
	if threshold <= 0 {
		threshold = baseline * 3 // Trigger back-off if latency > 3x baseline
	}

	return &CircuitBreaker{
		state:              models.StateClosed,
		tripReason:         models.ReasonNone,
		consecutive5xxCap:  fiveXxCap,
		baselineLatencyMs:  baseline,
		movingAvgLatencyMs: baseline,
		latencyThresholdMs: threshold,
		currentRPS:         float64(maxRPS),
		configuredMaxRPS:   maxRPS,
		lastStateChange:    time.Now(),
		cooldownDuration:   15 * time.Second,
	}
}

// CanExecute checks if an HTTP request is permitted to fire
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	// If OPEN, check if cooldown has elapsed to enter HALF_OPEN
	if cb.state == models.StateOpen {
		if now.After(cb.cooldownEndsAt) {
			cb.state = models.StateHalfOpen
			cb.lastStateChange = now
			cb.successProbeCount = 0
			return true // Allow one probe request
		}
		return false
	}

	return true
}

// RecordResponse inspects response status code and round-trip duration to update circuit breaker state (FR-4.3, FR-4.4)
func (cb *CircuitBreaker) RecordResponse(statusCode int, durationMs int64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	// Update Exponential Moving Average (EMA) of latency: alpha = 0.2
	alpha := 0.2
	cb.movingAvgLatencyMs = int64(float64(cb.movingAvgLatencyMs)*(1.0-alpha) + float64(durationMs)*alpha)

	// FR-4.3: 5xx Circuit Breaker
	if statusCode >= 500 && statusCode <= 599 {
		cb.consecutive5xx++
		if cb.consecutive5xx >= cb.consecutive5xxCap {
			cb.state = models.StateOpen
			cb.tripReason = models.ReasonConsecutive5xx
			cb.totalTrips++
			cb.lastStateChange = now
			cb.cooldownEndsAt = now.Add(cb.cooldownDuration)
			return
		}
	} else if statusCode > 0 {
		// Non-5xx response resets consecutive counter
		cb.consecutive5xx = 0
		if cb.state == models.StateHalfOpen {
			cb.successProbeCount++
			if cb.successProbeCount >= 3 {
				// 3 consecutive successful probes recover the circuit
				cb.state = models.StateClosed
				cb.tripReason = models.ReasonNone
				cb.lastStateChange = now
			}
		}
	}

	// FR-4.4: Dynamic Latency Back-off
	if cb.state == models.StateClosed || cb.state == models.StateThrottled {
		if cb.movingAvgLatencyMs > cb.latencyThresholdMs {
			// Severe latency: throttle RPS down by 50%
			cb.state = models.StateThrottled
			cb.tripReason = models.ReasonLatencySpike
			newRPS := cb.currentRPS * 0.5
			if newRPS < 2.0 {
				newRPS = 2.0
			}
			cb.currentRPS = newRPS
		} else if cb.state == models.StateThrottled && cb.movingAvgLatencyMs <= (cb.baselineLatencyMs*3/2) {
			// Latency returned close to baseline: gently restore RPS
			cb.currentRPS += 2.0
			if cb.currentRPS >= float64(cb.configuredMaxRPS) {
				cb.currentRPS = float64(cb.configuredMaxRPS)
				cb.state = models.StateClosed
				cb.tripReason = models.ReasonNone
			}
		}
	}
}

// ForceTrip manually trips the circuit breaker (e.g. abort or fatal target crash)
func (cb *CircuitBreaker) ForceTrip(reason models.TripReason) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = models.StateOpen
	cb.tripReason = reason
	cb.totalTrips++
	cb.lastStateChange = time.Now()
	cb.cooldownEndsAt = time.Now().Add(1 * time.Hour) // Requires manual un-trip or abort
}

// GetCurrentRPS returns the dynamic throttle limit
func (cb *CircuitBreaker) GetCurrentRPS() float64 {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.currentRPS
}

// GetTelemetry provides current status for monitoring and reporting
func (cb *CircuitBreaker) GetTelemetry() models.CircuitBreakerTelemetry {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return models.CircuitBreakerTelemetry{
		CurrentState:        cb.state,
		TripReason:          cb.tripReason,
		Consecutive5xxCount: cb.consecutive5xx,
		Consecutive5xxCap:   cb.consecutive5xxCap,
		BaselineLatencyMs:   cb.baselineLatencyMs,
		MovingAvgLatencyMs:  cb.movingAvgLatencyMs,
		LatencyThresholdMs:  cb.latencyThresholdMs,
		CurrentRPS:          cb.currentRPS,
		ConfiguredMaxRPS:    cb.configuredMaxRPS,
		TotalTripsCount:     cb.totalTrips,
		LastStateChange:     cb.lastStateChange,
		CooldownEndsAt:      cb.cooldownEndsAt,
	}
}
