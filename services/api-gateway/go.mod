module github.com/vyomite/dast/services/api-gateway

go 1.22

require (
	github.com/google/uuid v1.6.0
	github.com/vyomite/dast/pkg/models v0.0.0
	github.com/vyomite/dast/services/scan-worker v0.0.0
)

replace github.com/vyomite/dast/pkg/models => ../../pkg/models
replace github.com/vyomite/dast/services/scan-worker => ../scan-worker
