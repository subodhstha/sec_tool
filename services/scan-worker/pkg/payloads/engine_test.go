package payloads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildInjectedRequestJSONEscapesStringValues(t *testing.T) {
	_, body := (&Engine{}).buildInjectedRequest("https://example.test", "query", `"quoted"`, ContextJSONBody)

	var document map[string]string
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("JSON body is invalid: %v", err)
	}
	if document["query"] != `"quoted"` {
		t.Fatalf("unexpected JSON value: %q", document["query"])
	}
}

func TestBuildInjectedRequestReplacesPathPlaceholder(t *testing.T) {
	got, _ := (&Engine{}).buildInjectedRequest("https://example.test/users/{id}", "id", "probe", ContextURLPath)
	if got != "https://example.test/users/probe" {
		t.Fatalf("path placeholder was not replaced: %s", got)
	}
}

func TestInjectParameterSendsMultipartPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1024 * 1024); err != nil {
			t.Fatalf("multipart form parse failed: %v", err)
		}
		files := r.MultipartForm.File["upload"]
		if len(files) != 1 || files[0].Filename != "probe.txt" {
			t.Errorf("unexpected uploaded file: %+v", files)
		}
		file, err := files[0].Open()
		if err != nil {
			t.Fatalf("uploaded file open failed: %v", err)
		}
		defer file.Close()
		w.Write([]byte("multipart-hit"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatFileUpload, Payloads: []Payload{{
		ID: "multipart-upload", Category: CatFileUpload, Name: "upload", Value: "probe.txt",
		Contexts: []InjectionContext{ContextMultipart}, Detection: DetectReflection,
		DetectSignature: "multipart-hit", SafeMode: true,
	}}})
	engine := NewEngine(registry, DefaultEngineConfig())
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodPost, "upload", ContextMultipart)
	if len(results) != 1 || !results[0].Detected {
		t.Fatalf("expected multipart finding, got %+v", results)
	}
}

func TestInjectParameterSendsHeaderAndCookieContexts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			if r.Header.Get("Origin") != "https://evil.example" {
				t.Errorf("Origin header = %q", r.Header.Get("Origin"))
			}
		} else {
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "probe-value" {
				t.Errorf("session cookie = %v", err)
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("probe-hit"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatCORS, Payloads: []Payload{{
		ID: "test-header", Category: CatCORS, Name: "header", Value: "https://evil.example",
		Contexts: []InjectionContext{ContextHTTPHeader}, Detection: DetectReflection,
		DetectSignature: "probe-hit", SafeMode: true,
	}}})
	registry.RegisterCustomSet(PayloadSet{Category: CatJWT, Payloads: []Payload{{
		ID: "test-cookie", Category: CatJWT, Name: "cookie", Value: "probe-value",
		Contexts: []InjectionContext{ContextCookie}, Detection: DetectReflection,
		DetectSignature: "probe-hit", SafeMode: true,
	}}})

	engine := NewEngine(registry, DefaultEngineConfig())
	headerResults := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "Origin", ContextHTTPHeader)
	cookieResults := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "session", ContextCookie)
	if len(headerResults) != 1 || len(cookieResults) != 1 {
		t.Fatalf("expected one header and cookie result, got %d and %d", len(headerResults), len(cookieResults))
	}
}

func TestInjectParameterReflectionMatchesResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Vyomite-DAST", "crlf-injected")
		_, _ = w.Write([]byte("ordinary body"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatCRLF, Payloads: []Payload{{
		ID: "header-reflection", Category: CatCRLF, Name: "header reflection", Value: "probe",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectReflection,
		DetectSignature: `X-Vyomite-DAST:\s*crlf-injected`, SafeMode: true,
	}}})
	engine := NewEngine(registry, DefaultEngineConfig())
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "q", ContextURLQuery)
	if len(results) != 1 || !results[0].Detected {
		t.Fatalf("expected response-header reflection finding, got %+v", results)
	}
}

func TestInjectParameterDeduplicationIsScopedToTarget(t *testing.T) {
	newServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("target-hit"))
		}))
	}
	first := newServer()
	defer first.Close()
	second := newServer()
	defer second.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatXSS, Payloads: []Payload{{
		ID: "target-scoped", Category: CatXSS, Name: "target scoped", Value: "probe",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectReflection,
		DetectSignature: "target-hit", SafeMode: true,
	}}})
	engine := NewEngine(registry, DefaultEngineConfig())
	firstResults := engine.InjectParameter(context.Background(), first.URL, http.MethodGet, "q", ContextURLQuery)
	secondResults := engine.InjectParameter(context.Background(), second.URL, http.MethodGet, "q", ContextURLQuery)
	if len(firstResults) != 1 || len(secondResults) != 1 {
		t.Fatalf("payload was incorrectly deduplicated across targets: first=%d second=%d", len(firstResults), len(secondResults))
	}
}

func TestInjectParameterWithHeadersMergesAuthAndEndpointHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer endpoint" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Tenant") != "acme" {
			t.Errorf("X-Tenant header = %q", r.Header.Get("X-Tenant"))
		}
		_, _ = w.Write([]byte("header-context-hit"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatSQLi, Payloads: []Payload{{
		ID: "header-context", Category: CatSQLi, Name: "header context", Value: "probe",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectReflection,
		DetectSignature: "header-context-hit", SafeMode: true,
	}}})
	config := DefaultEngineConfig()
	config.Headers = map[string]string{"Authorization": "Bearer auth", "X-Tenant": "acme"}
	engine := NewEngine(registry, config)
	results := engine.InjectParameterWithHeaders(context.Background(), server.URL, http.MethodGet, "q", ContextURLQuery, map[string]string{"Authorization": "Bearer endpoint"})
	if len(results) != 1 {
		t.Fatalf("expected one header-context result, got %d", len(results))
	}
}

func TestInjectParameterAppliesProfilePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("profile-hit"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatSQLi, Payloads: []Payload{
		{ID: "profile-safe", Category: CatSQLi, Value: "safe", Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectReflection, DetectSignature: "profile-hit", Severity: SevLow, SafeMode: true},
		{ID: "profile-active", Category: CatSQLi, Value: "active", Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectReflection, DetectSignature: "profile-hit", Severity: SevHigh, SafeMode: false},
		{ID: "profile-time", Category: CatSQLi, Value: "time", Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectTimeDelta, Severity: SevMedium, SafeMode: true},
	}})

	config := DefaultEngineConfig()
	config.Profile = ProfileLight
	config.MaxPayloadsPerParam = 0
	engine := NewEngine(registry, config)
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "q", ContextURLQuery)
	if len(results) != 1 || results[0].PayloadID != "profile-safe" {
		t.Fatalf("profile selected unexpected payloads: %+v", results)
	}
}

func TestInjectParameterDetectsContentDiffAgainstBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "" {
			_, _ = w.Write([]byte("baseline"))
			return
		}
		_, _ = w.Write([]byte("changed response from payload"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatIDOR, Payloads: []Payload{{
		ID: "content-diff", Category: CatIDOR, Name: "diff", Value: "victim",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectContentDiff,
		Severity: SevHigh, SafeMode: true,
	}}})
	config := DefaultEngineConfig()
	config.ContentDiffThresholdBytes = 1
	engine := NewEngine(registry, config)
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "q", ContextURLQuery)
	if len(results) != 1 || !results[0].Detected {
		t.Fatalf("expected content difference finding, got %+v", results)
	}
}

func TestInjectParameterStatusCodeRequiresBaselineDifference(t *testing.T) {
	newServer := func(status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("q") == "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("baseline"))
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte("baseline"))
		}))
	}

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatSSRF, Payloads: []Payload{{
		ID: "status-code", Category: CatSSRF, Name: "status", Value: "internal",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectStatusCode,
		Severity: SevHigh, SafeMode: true,
	}}})

	unchanged := newServer(http.StatusOK)
	config := DefaultEngineConfig()
	engine := NewEngine(registry, config)
	unchangedResults := engine.InjectParameter(context.Background(), unchanged.URL, http.MethodGet, "q", ContextURLQuery)
	unchanged.Close()
	if len(unchangedResults) != 0 {
		t.Fatalf("unchanged status response was reported: %+v", unchangedResults)
	}

	changed := newServer(http.StatusFound)
	defer changed.Close()
	changedResults := engine.InjectParameter(context.Background(), changed.URL, http.MethodGet, "q", ContextURLQuery)
	if len(changedResults) != 1 || !changedResults[0].Detected {
		t.Fatalf("changed status response was not reported: %+v", changedResults)
	}
}

func TestInjectParameterDetectsResponseHeaderSignature(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://evil.example")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cors response"))
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatCORS, Payloads: []Payload{{
		ID: "cors-header", Category: CatCORS, Name: "origin reflection", Value: "https://evil.example",
		Contexts: []InjectionContext{ContextHTTPHeader}, Detection: DetectHeaderInject,
		DetectSignature: `Access-Control-Allow-Origin:\s*https://evil\.example`, SafeMode: true,
	}}})
	engine := NewEngine(registry, DefaultEngineConfig())
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "Origin", ContextHTTPHeader)
	if len(results) != 1 || !results[0].Detected {
		t.Fatalf("expected response header finding, got %+v", results)
	}
}

func TestInjectParameterDetectsRedirectLocationChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") == "" {
			w.Header().Set("Location", "/safe")
		} else {
			w.Header().Set("Location", "https://evil.example")
		}
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	registry := &Registry{sets: make(map[PayloadCategory]PayloadSet)}
	registry.RegisterCustomSet(PayloadSet{Category: CatOpenRedirect, Payloads: []Payload{{
		ID: "redirect-location", Category: CatOpenRedirect, Name: "redirect", Value: "https://evil.example",
		Contexts: []InjectionContext{ContextURLQuery}, Detection: DetectStatusCode,
		Severity: SevMedium, SafeMode: true,
	}}})
	engine := NewEngine(registry, DefaultEngineConfig())
	results := engine.InjectParameter(context.Background(), server.URL, http.MethodGet, "next", ContextURLQuery)
	if len(results) != 1 || !results[0].Detected {
		t.Fatalf("expected redirect location finding, got %+v", results)
	}
}
