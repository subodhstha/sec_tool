package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vyomite/dast/pkg/models"
)

// SessionManager manages authenticated scan states and automatic re-authentication (FR-2.1, FR-2.2)
type SessionManager struct {
	mu           sync.RWMutex
	macro        *models.AuthMacro
	httpClient   *http.Client
	isRefreshing bool
	refreshCond  *sync.Cond
}

// NewSessionManager creates a session manager for the target scan
func NewSessionManager(macro *models.AuthMacro) *SessionManager {
	sm := &SessionManager{
		macro: macro,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	sm.refreshCond = sync.NewCond(&sm.mu)
	return sm
}

// GetAuthHeaders returns current authorization headers, waiting if a session refresh is currently in progress
func (sm *SessionManager) GetAuthHeaders() map[string]string {
	if sm.macro == nil {
		return nil
	}

	sm.mu.Lock()
	for sm.isRefreshing {
		sm.refreshCond.Wait()
	}
	defer sm.mu.Unlock()

	headers := make(map[string]string)
	for k, v := range sm.macro.StaticHeaders {
		headers[k] = v
	}

	if sm.macro.CurrentToken != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", sm.macro.CurrentToken)
	}

	return headers
}

// CheckHeartbeat verifies if the session is still active via the Heartbeat URL (FR-2.2)
func (sm *SessionManager) CheckHeartbeat(ctx context.Context) (bool, error) {
	if sm.macro == nil || sm.macro.HeartbeatURL == "" {
		return true, nil // No heartbeat configured, assume active
	}

	headers := sm.GetAuthHeaders()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sm.macro.HeartbeatURL, nil)
	if err != nil {
		return false, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If 401 Unauthorized or 403 Forbidden, session has expired
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return false, nil
	}

	return true, nil
}

// RecoverSession pauses fuzzing, replays the login macro, and acquires a fresh session (FR-2.2)
func (sm *SessionManager) RecoverSession(ctx context.Context) error {
	if sm.macro == nil {
		return nil
	}

	sm.mu.Lock()
	if sm.isRefreshing {
		// Another goroutine is already refreshing; wait for it
		sm.refreshCond.Wait()
		sm.mu.Unlock()
		return nil
	}

	sm.isRefreshing = true
	sm.mu.Unlock()

	defer func() {
		sm.mu.Lock()
		sm.isRefreshing = false
		sm.refreshCond.Broadcast()
		sm.mu.Unlock()
	}()

	// Execute Macro Replay (FR-2.1)
	freshToken, err := sm.executeMacro(ctx)
	if err != nil {
		return fmt.Errorf("session recovery failed: %w", err)
	}

	sm.mu.Lock()
	sm.macro.CurrentToken = freshToken
	sm.macro.LastRefresh = time.Now()
	sm.mu.Unlock()

	return nil
}

// executeMacro executes the configured steps to fetch new tokens (FR-2.1)
func (sm *SessionManager) executeMacro(ctx context.Context) (string, error) {
	if sm.macro.LoginURL == "" {
		return "", fmt.Errorf("macro login_url is empty")
	}

	// Prepare payload if JSON login step is present
	payloadMap := make(map[string]interface{})
	for _, step := range sm.macro.Steps {
		if step.Action == models.ActionType && step.ExtractName != "" {
			payloadMap[step.ExtractName] = step.Value
		}
	}

	bodyBytes, _ := json.Marshal(payloadMap)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sm.macro.LoginURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := sm.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("login macro endpoint returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse JSON response to extract access_token or token
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err == nil {
		if token, ok := result["token"].(string); ok && token != "" {
			return token, nil
		}
		if token, ok := result["access_token"].(string); ok && token != "" {
			return token, nil
		}
		if token, ok := result["jwt"].(string); ok && token != "" {
			return token, nil
		}
	}

	// Check Set-Cookie headers for session cookies
	if cookies := resp.Cookies(); len(cookies) > 0 {
		for _, c := range cookies {
			if c.Name == "session" || c.Name == "token" || c.Name == "jwt" {
				return c.Value, nil
			}
		}
		return cookies[0].Value, nil
	}

	return "", fmt.Errorf("could not extract token or cookie from login macro response")
}
