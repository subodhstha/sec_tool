package fuzzer

import (
	"testing"

	"github.com/vyomite/dast/services/scan-worker/pkg/payloads"
)

func TestMapEndpointParamToContextUsesGraphQLSource(t *testing.T) {
	if got := mapEndpointParamToContext("GRAPHQL", "json"); got != payloads.ContextGraphQL {
		t.Fatalf("GraphQL source mapped to %q", got)
	}
}

func TestMapEndpointParamToContextPreservesNonGraphQLLocations(t *testing.T) {
	if got := mapEndpointParamToContext("OPENAPI", "header"); got != payloads.ContextHTTPHeader {
		t.Fatalf("OpenAPI header mapped to %q", got)
	}
}
