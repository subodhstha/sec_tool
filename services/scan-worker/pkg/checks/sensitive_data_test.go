package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInformationDisclosureAuditor_AuditResponseBody(t *testing.T) {
	auditor := NewInformationDisclosureAuditor()

	tests := []struct {
		name          string
		body          string
		expectedTitle string
		expectedCount int
	}{
		{
			name:          "Java Stack Trace",
			body:          `<html><body><h1>Error</h1><pre>java.lang.NullPointerException&#10;&#09;at com.example.MyClass.method(MyClass.java:10)</pre></body></html>`,
			expectedTitle: "Stack Trace / Debug Information Exposure: Java / Spring Stack Trace",
			expectedCount: 1,
		},
		{
			name:          "AWS Access Key",
			body:          `{"key": "AKIAIOSFODNN7EXAMPLE", "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
			expectedTitle: "AWS Access Key Leak",
			expectedCount: 1,
		},
		{
			name:          "GCP Service Account Key",
			body:          `{ "type": "service_account", "project_id": "my-project", "private_key_id": "123", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIB...-----END PRIVATE KEY-----\n" }`,
			expectedTitle: "Google Cloud / GCP Service Account Key",
			expectedCount: 2, // Matches both Private Key and GCP Service Account Key
		},
		{
			name:          "Clean Response",
			body:          `{"status": "ok", "message": "hello world"}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}

			findings := auditor.AuditResponseBody("scan-123", "http://example.com", req, resp, tt.body)
			if len(findings) != tt.expectedCount {
				t.Fatalf("expected %d findings, got %d", tt.expectedCount, len(findings))
			}

			if tt.expectedCount > 0 {
				found := false
				for _, f := range findings {
					if strings.Contains(f.Title, tt.expectedTitle) || strings.Contains(f.Description, tt.expectedTitle) {
						found = true
						break
					}
					if f.Title == tt.expectedTitle {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected to find a finding with title/desc containing: %s", tt.expectedTitle)
				}
			}
		})
	}
}

func TestInformationDisclosureAuditor_AuditServerVersionHeaders(t *testing.T) {
	auditor := NewInformationDisclosureAuditor()

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "nginx/1.22.1")
	resp.Header.Set("X-Powered-By", "PHP/8.1.2")

	findings := auditor.AuditServerVersionHeaders("scan-123", "http://example.com", req, resp)

	if len(findings) != 2 {
		t.Fatalf("expected 2 version disclosure findings, got %d", len(findings))
	}
}

func TestInformationDisclosureAuditor_AuditDebugEndpoints(t *testing.T) {
	auditor := NewInformationDisclosureAuditor()

	// Mock server that responds to /actuator/env
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Received request: %s", r.URL.Path)
		if r.URL.Path == "/actuator/env" {
			w.WriteHeader(http.StatusOK)
			// The signature for /actuator/env is "\"property\""
			w.Write([]byte(`{"propertySources":[{"name":"systemProperties","property":{"java.runtime.name":{"value":"OpenJDK Runtime Environment"}}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	findings := auditor.AuditDebugEndpoints(context.Background(), "scan-123", ts.URL, ts.Client())
	t.Logf("Found %d findings: %+v", len(findings), findings)

	// We expect 1 finding for /actuator/env
	if len(findings) != 1 {
		t.Fatalf("expected 1 debug endpoint finding, got %d", len(findings))
	}
	
	if !strings.Contains(findings[0].Title, "Spring Boot Actuator /env Exposed") {
		t.Errorf("expected finding title 'Spring Boot Actuator /env Exposed', got: %s", findings[0].Title)
	}
}
