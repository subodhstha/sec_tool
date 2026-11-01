package models

import (
	"time"
)

// CBState indicates the health status of the scanning circuit breaker
type CBState string

const (
	StateClosed    CBState = "CLOSED"     // Normal scanning operation
	StateOpen      CBState = "OPEN"       // Tripped: scanning paused
	StateHalfOpen  CBState = "HALF_OPEN"  // Probing target recovery
	StateThrottled CBState = "THROTTLED"  // Back-off active: request rate throttled
)

// TripReason explains why the circuit breaker was activated
type TripReason string

const (
	ReasonNone              TripReason = "NONE"
	ReasonConsecutive5xx    TripReason = "CONSECUTIVE_5XX_THRESHOLD_EXCEEDED"
	ReasonLatencySpike      TripReason = "LATENCY_THRESHOLD_EXCEEDED"
	ReasonManualAbort       TripReason = "MANUAL_ABORT_TRIGGERED"
	ReasonConnectionRefused TripReason = "TARGET_CONNECTION_REFUSED"
)

// CircuitBreakerTelemetry tracks the real-time safety status of a target
type CircuitBreakerTelemetry struct {
	CurrentState        CBState    `json:"current_state"`
	TripReason          TripReason `json:"trip_reason"`
	Consecutive5xxCount int        `json:"consecutive_5xx_count"`
	Consecutive5xxCap   int        `json:"consecutive_5xx_cap"`
	BaselineLatencyMs   int64      `json:"baseline_latency_ms"`
	MovingAvgLatencyMs  int64      `json:"moving_avg_latency_ms"`
	LatencyThresholdMs  int64      `json:"latency_threshold_ms"`
	CurrentRPS          float64    `json:"current_rps"`
	ConfiguredMaxRPS    int        `json:"configured_max_rps"`
	TotalTripsCount     int        `json:"total_trips_count"`
	LastStateChange     time.Time  `json:"last_state_change"`
	CooldownEndsAt      time.Time  `json:"cooldown_ends_at,omitempty"`
}
