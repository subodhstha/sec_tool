package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vyomite/dast/pkg/models"
	"github.com/vyomite/dast/services/scan-worker/pkg/sanitizer"
)

type SensitiveFileTarget struct {
	Path        string
	Signature   string // Required content substring to confirm finding without false positives
	Title       string
	Severity    models.VulnerabilitySeverity
	CVSS        float64
	CWE         string
	Description string
	Remediation string
}

var sensitivePaths = []SensitiveFileTarget{
	// ═══════════ VCS & Source Code Exposure ═══════════
	{
		Path: "/.git/HEAD", Signature: "ref: refs/",
		Title: "Exposed Git Repository Root (/.git/HEAD)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-538",
		Description: "The production server allows direct access to the /.git repository, allowing complete source code, history, and secret exfiltration.",
		Remediation: "Block access to the /.git directory in your web server configuration and delete .git folders in production.",
	},
	{
		Path: "/.git/config", Signature: "[core]",
		Title: "Git Config File Exposed (/.git/config)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-538",
		Description: "The Git configuration file is accessible, revealing remote repository URLs (potentially with credentials), branch tracking info, and author details.",
		Remediation: "Block access to the entire /.git directory tree.",
	},
	{
		Path: "/.svn/entries", Signature: "",
		Title: "Exposed SVN Repository Metadata (/.svn/entries)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-538",
		Description: "Subversion repository metadata is accessible, allowing reconstruction of source code and repository history.",
		Remediation: "Block access to /.svn directories in web server configuration.",
	},
	{
		Path: "/.hg/hgrc", Signature: "",
		Title: "Exposed Mercurial Repository Config (/.hg/hgrc)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-538",
		Description: "Mercurial repository configuration is accessible, revealing remote repository URLs and extensions.",
		Remediation: "Block access to /.hg directories in web server configuration.",
	},
	{
		Path: "/.bzr/README", Signature: "",
		Title: "Exposed Bazaar Repository (/.bzr/)", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-538",
		Description: "Bazaar VCS metadata is accessible, potentially exposing source code and commit history.",
		Remediation: "Block access to /.bzr directories.",
	},

	// ═══════════ Environment & Secret Files ═══════════
	{
		Path: "/.env", Signature: "=",
		Title: "Exposed Environment Secrets File (/.env)", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-552",
		Description: "The application exposes an unencrypted .env file containing database credentials, API keys, and environment variables.",
		Remediation: "Deny dotfile access in web server configuration. Never deploy .env files to production web roots.",
	},
	{
		Path: "/.env.production", Signature: "=",
		Title: "Exposed Production Environment File (/.env.production)", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-552",
		Description: "Production-specific environment file is publicly accessible with production credentials.",
		Remediation: "Block all .env* files from web serving.",
	},
	{
		Path: "/.env.local", Signature: "=",
		Title: "Exposed Local Environment File (/.env.local)", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-552",
		Description: "Local environment override file is accessible, potentially containing developer credentials.",
		Remediation: "Block all .env* files from web serving.",
	},
	{
		Path: "/.env.backup", Signature: "=",
		Title: "Exposed Environment Backup File (/.env.backup)", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-552",
		Description: "Environment backup file with credentials is publicly accessible.",
		Remediation: "Remove backup files from web-accessible directories.",
	},

	// ═══════════ Configuration Files ═══════════
	{
		Path: "/config.json", Signature: "{",
		Title: "Exposed Configuration File (config.json)", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-552",
		Description: "Application configuration file in JSON format is publicly accessible, potentially containing database connection strings, API keys, or internal service endpoints.",
		Remediation: "Move configuration files outside the web root or block access via web server rules.",
	},
	{
		Path: "/config.yml", Signature: "",
		Title: "Exposed Configuration File (config.yml)", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-552",
		Description: "YAML configuration file is publicly accessible.",
		Remediation: "Move configuration files outside the web root.",
	},
	{
		Path: "/config.php", Signature: "<?",
		Title: "Exposed PHP Configuration File", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-552",
		Description: "PHP configuration file is accessible and may contain database credentials and API secrets.",
		Remediation: "Ensure PHP configuration files are not in web-accessible directories.",
	},
	{
		Path: "/web.config", Signature: "configuration",
		Title: "Exposed IIS web.config File", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-552",
		Description: "IIS web.config file is accessible, potentially revealing connection strings, authentication settings, and custom error configurations.",
		Remediation: "Ensure web.config files are protected by IIS configuration.",
	},
	{
		Path: "/WEB-INF/web.xml", Signature: "web-app",
		Title: "Java WEB-INF/web.xml Exposed", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-538",
		Description: "Java web application deployment descriptor is accessible, revealing servlet mappings, security constraints, and internal architecture.",
		Remediation: "Ensure the application server properly restricts access to WEB-INF directory.",
	},
	{
		Path: "/application.properties", Signature: "",
		Title: "Spring Boot application.properties Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-552",
		Description: "Spring Boot application properties file is accessible, potentially containing database URLs, passwords, and secret keys.",
		Remediation: "Move properties files outside the web root.",
	},

	// ═══════════ Backup & Dump Files ═══════════
	{
		Path: "/backup.sql", Signature: "",
		Title: "SQL Database Dump File Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "A SQL database dump file is publicly accessible, potentially containing complete database contents including user credentials, personal data, and business logic.",
		Remediation: "Remove all database dumps from web-accessible directories. Store backups in encrypted, access-controlled storage.",
	},
	{
		Path: "/database.sql", Signature: "",
		Title: "Database SQL File Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "Database SQL file is publicly accessible.",
		Remediation: "Remove database files from web-accessible directories.",
	},
	{
		Path: "/dump.sql", Signature: "",
		Title: "SQL Dump File Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "SQL dump file is publicly accessible.",
		Remediation: "Remove dump files from web-accessible directories.",
	},
	{
		Path: "/backup.zip", Signature: "PK",
		Title: "Backup Archive File Exposed (backup.zip)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-530",
		Description: "A ZIP backup archive is publicly downloadable, potentially containing full application source code, configuration, and credentials.",
		Remediation: "Remove all backup archives from web-accessible directories.",
	},
	{
		Path: "/backup.tar.gz", Signature: "",
		Title: "Backup Archive File Exposed (backup.tar.gz)", Severity: models.SeverityCritical, CVSS: 9.1, CWE: "CWE-530",
		Description: "A tar.gz backup archive is publicly downloadable.",
		Remediation: "Remove backup archives from web-accessible directories.",
	},

	// ═══════════ CI/CD & DevOps Files ═══════════
	{
		Path: "/.gitlab-ci.yml", Signature: "",
		Title: "GitLab CI/CD Configuration Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-538",
		Description: "GitLab CI/CD pipeline configuration is accessible, revealing build processes, deployment targets, secret variable names, and infrastructure details.",
		Remediation: "Block access to CI/CD configuration files in web server config.",
	},
	{
		Path: "/.github/workflows/", Signature: "",
		Title: "GitHub Actions Workflows Directory Exposed", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-538",
		Description: "GitHub Actions workflow directory is accessible, revealing CI/CD pipeline configurations.",
		Remediation: "Block access to .github directory.",
	},
	{
		Path: "/Jenkinsfile", Signature: "",
		Title: "Jenkinsfile Pipeline Configuration Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-538",
		Description: "Jenkins pipeline configuration is accessible, revealing build stages, deployment targets, and potentially secret references.",
		Remediation: "Block access to Jenkinsfile from web server.",
	},
	{
		Path: "/Dockerfile", Signature: "FROM",
		Title: "Dockerfile Exposed", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-538",
		Description: "Docker build configuration is accessible, revealing base images, build steps, and potentially embedded credentials or internal URLs.",
		Remediation: "Block access to Dockerfile from web server.",
	},
	{
		Path: "/docker-compose.yml", Signature: "",
		Title: "Docker Compose Configuration Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-538",
		Description: "Docker Compose file is accessible, revealing service architecture, environment variables, ports, and volume mounts.",
		Remediation: "Block access to docker-compose files from web server.",
	},

	// ═══════════ Package Manager & Dependency Files ═══════════
	{
		Path: "/package.json", Signature: "\"name\"",
		Title: "Node.js package.json Exposed", Severity: models.SeverityLow, CVSS: 3.7, CWE: "CWE-200",
		Description: "Node.js package manifest is accessible, revealing dependency versions (enabling targeted CVE exploitation), private registry URLs, and scripts.",
		Remediation: "Block access to package.json from public-facing web servers.",
	},
	{
		Path: "/composer.json", Signature: "\"require\"",
		Title: "PHP Composer Manifest Exposed", Severity: models.SeverityLow, CVSS: 3.7, CWE: "CWE-200",
		Description: "PHP Composer manifest is accessible, revealing PHP dependencies and versions.",
		Remediation: "Block access to composer.json from web server.",
	},
	{
		Path: "/Gemfile", Signature: "source",
		Title: "Ruby Gemfile Exposed", Severity: models.SeverityLow, CVSS: 3.7, CWE: "CWE-200",
		Description: "Ruby Gemfile is accessible, revealing Ruby gem dependencies and versions.",
		Remediation: "Block access to Gemfile from web server.",
	},
	{
		Path: "/requirements.txt", Signature: "",
		Title: "Python requirements.txt Exposed", Severity: models.SeverityLow, CVSS: 3.7, CWE: "CWE-200",
		Description: "Python requirements file is accessible, revealing Python package dependencies and versions.",
		Remediation: "Block access to requirements.txt from web server.",
	},

	// ═══════════ CMS & Framework Files ═══════════
	{
		Path: "/wp-config.php.bak", Signature: "",
		Title: "WordPress Configuration Backup Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "WordPress configuration backup file is accessible, containing database credentials and authentication keys in plain text.",
		Remediation: "Remove all .bak files from WordPress installations.",
	},
	{
		Path: "/wp-login.php", Signature: "WordPress",
		Title: "WordPress Login Page Discovered", Severity: models.SeverityInfo, CVSS: 0.0, CWE: "CWE-200",
		Description: "WordPress login page is publicly accessible, enabling brute-force attack surface identification.",
		Remediation: "Consider restricting wp-login.php access by IP or implementing two-factor authentication.",
	},
	{
		Path: "/administrator/", Signature: "",
		Title: "Admin Panel Directory Discovered", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-200",
		Description: "An administrator panel directory was discovered, expanding the attack surface.",
		Remediation: "Restrict admin panel access to trusted IP ranges. Use strong authentication and rate limiting.",
	},

	// ═══════════ Diagnostic & Debug Files ═══════════
	{
		Path: "/phpinfo.php", Signature: "PHP Version",
		Title: "Exposed PHP Environment Diagnostic (phpinfo.php)", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-200",
		Description: "phpinfo() is exposed, revealing PHP version, compile flags, extensions, and environment variables.",
		Remediation: "Remove diagnostic scripts from production environments.",
	},
	{
		Path: "/info.php", Signature: "PHP Version",
		Title: "PHP Info Page Exposed (info.php)", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-200",
		Description: "PHP information page is exposed.",
		Remediation: "Remove diagnostic scripts from production.",
	},
	{
		Path: "/test.php", Signature: "",
		Title: "Test PHP Script Exposed", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-200",
		Description: "A test PHP script is accessible in production, which may contain debug functionality or information disclosure.",
		Remediation: "Remove test scripts from production environments.",
	},

	// ═══════════ SSH & Crypto Keys ═══════════
	{
		Path: "/.ssh/id_rsa", Signature: "-----BEGIN",
		Title: "SSH Private Key Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-312",
		Description: "An SSH private key file is publicly accessible, granting potential remote access to servers.",
		Remediation: "Remove SSH key files from web-accessible directories immediately and rotate all affected keys.",
	},
	{
		Path: "/.ssh/authorized_keys", Signature: "ssh-",
		Title: "SSH Authorized Keys File Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-200",
		Description: "SSH authorized_keys file is accessible, revealing public keys allowed for SSH access.",
		Remediation: "Block access to .ssh directory from web server.",
	},

	// ═══════════ Metadata & Reconnaissance ═══════════
	{
		Path: "/robots.txt", Signature: "User-agent:",
		Title: "Discovered robots.txt Information Metafile", Severity: models.SeverityInfo, CVSS: 0.0, CWE: "CWE-200",
		Description: "robots.txt metafile discovered, disclosing disallow directives and potentially sensitive paths.",
		Remediation: "Ensure disallow directives do not disclose sensitive administrative endpoints.",
	},
	{
		Path: "/sitemap.xml", Signature: "urlset",
		Title: "Sitemap XML Discovered", Severity: models.SeverityInfo, CVSS: 0.0, CWE: "CWE-200",
		Description: "Sitemap file discovered, revealing the full structure of accessible URLs.",
		Remediation: "Ensure sitemap does not include admin, internal, or staging URLs.",
	},
	{
		Path: "/security.txt", Signature: "",
		Title: "Security Policy File Discovered (/.well-known/security.txt)", Severity: models.SeverityInfo, CVSS: 0.0, CWE: "CWE-200",
		Description: "A security.txt file was found, disclosing the responsible disclosure policy.",
		Remediation: "This is generally good practice. Ensure no internal contact details are leaked.",
	},
	{
		Path: "/.well-known/security.txt", Signature: "",
		Title: "Security Policy at Standard Location", Severity: models.SeverityInfo, CVSS: 0.0, CWE: "CWE-200",
		Description: "Security policy file found at RFC 9116 standard location.",
		Remediation: "Review contents to ensure no unintended internal information is disclosed.",
	},
	{
		Path: "/crossdomain.xml", Signature: "cross-domain-policy",
		Title: "Flash Cross-Domain Policy File Found", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-942",
		Description: "A Flash cross-domain policy file allows cross-origin data access, which could be exploited if overly permissive.",
		Remediation: "Remove crossdomain.xml if Flash is not used, or restrict to specific trusted domains.",
	},

	// ═══════════ Log Files ═══════════
	{
		Path: "/error.log", Signature: "",
		Title: "Error Log File Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-532",
		Description: "Server error log file is publicly accessible, potentially revealing application errors, stack traces, file paths, and query parameters with sensitive data.",
		Remediation: "Move log files outside the web root. Block access to *.log files in web server configuration.",
	},
	{
		Path: "/access.log", Signature: "",
		Title: "Access Log File Exposed", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-532",
		Description: "Server access log is publicly accessible, revealing user IPs, request patterns, and query strings.",
		Remediation: "Move log files outside the web root.",
	},
	{
		Path: "/debug.log", Signature: "",
		Title: "Debug Log File Exposed", Severity: models.SeverityHigh, CVSS: 7.5, CWE: "CWE-532",
		Description: "Debug log file is publicly accessible, potentially containing verbose application state, variable dumps, and credentials.",
		Remediation: "Remove or block debug log files from production.",
	},
	{
		Path: "/app.log", Signature: "",
		Title: "Application Log File Exposed", Severity: models.SeverityMedium, CVSS: 5.3, CWE: "CWE-532",
		Description: "Application log file is publicly accessible.",
		Remediation: "Move log files outside the web root.",
	},

	// ═══════════ Database Files ═══════════
	{
		Path: "/db.sqlite3", Signature: "",
		Title: "SQLite Database File Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "A SQLite database file is publicly downloadable, potentially containing all application data including user credentials.",
		Remediation: "Move database files outside the web root.",
	},
	{
		Path: "/database.db", Signature: "",
		Title: "Database File Exposed (database.db)", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-530",
		Description: "A database file is publicly downloadable.",
		Remediation: "Move database files outside the web root.",
	},

	// ═══════════ Terraform & IaC ═══════════
	{
		Path: "/terraform.tfstate", Signature: "\"version\"",
		Title: "Terraform State File Exposed", Severity: models.SeverityCritical, CVSS: 9.8, CWE: "CWE-200",
		Description: "Terraform state file is publicly accessible, revealing complete infrastructure details including resource IDs, IP addresses, passwords, and API keys.",
		Remediation: "Never serve Terraform state files from web servers. Use remote state backends with encryption.",
	},

	// ═══════════ Editor & IDE Temp Files ═══════════
	{
		Path: "/.vscode/settings.json", Signature: "",
		Title: "VS Code Settings File Exposed", Severity: models.SeverityLow, CVSS: 3.1, CWE: "CWE-200",
		Description: "VS Code workspace settings are accessible, potentially revealing debug configurations and path information.",
		Remediation: "Block access to .vscode directory.",
	},
	{
		Path: "/.idea/workspace.xml", Signature: "",
		Title: "JetBrains IDE Workspace File Exposed", Severity: models.SeverityLow, CVSS: 3.1, CWE: "CWE-200",
		Description: "JetBrains IDE workspace configuration is accessible.",
		Remediation: "Block access to .idea directory.",
	},
}

// SensitiveFileProber probes common sensitive metadata files and exposed directories
type SensitiveFileProber struct{}

func NewSensitiveFileProber() *SensitiveFileProber {
	return &SensitiveFileProber{}
}

// ProbeRootPaths checks the target host for exposed files
func (p *SensitiveFileProber) ProbeRootPaths(
	ctx context.Context,
	scanID string,
	targetBaseURL string,
	client *http.Client,
) []models.VulnerabilityFinding {
	findings := make([]models.VulnerabilityFinding, 0)
	parsed, err := url.Parse(targetBaseURL)
	if err != nil {
		return findings
	}

	baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

	// Baseline Check for SPA Catch-All 404s
	catchAllBody := ""
	catchAllStatus := 404
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/vyomite-nonexistent-"+uuid.New().String(), nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			catchAllStatus = resp.StatusCode
			if resp.StatusCode == http.StatusOK {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
				catchAllBody = string(bodyBytes)
			}
			resp.Body.Close()
		}
	}

	for _, sf := range sensitivePaths {
		fileURL := baseURL + sf.Path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			bodySample, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()

			bodyStr := string(bodySample)
			contentType := strings.ToLower(resp.Header.Get("Content-Type"))
			
			// SPA / Catch-all false positive detection
			// If the response matches the baseline catch-all (like an SPA index.html), it's a false positive.
			isCatchAll := false
			if catchAllStatus == http.StatusOK && resp.StatusCode == http.StatusOK {
				if bodyStr == catchAllBody {
					isCatchAll = true
				}
			}

			// FR-4.5: False Positive Reduction - SPA Fallback Detection
			// We consider it an HTML fallback if the response is HTML and the target path
			// is not expected to execute server-side and return HTML (like .php or /).
			isHTMLFallback := false
			if !strings.HasSuffix(sf.Path, ".php") && !strings.HasSuffix(sf.Path, "/") {
				if strings.Contains(contentType, "text/html") || strings.HasPrefix(strings.TrimSpace(strings.ToLower(bodyStr)), "<!doctype html") || strings.HasPrefix(strings.TrimSpace(strings.ToLower(bodyStr)), "<html") {
					isHTMLFallback = true
				}
			}

			if !isCatchAll && !isHTMLFallback && (sf.Signature == "" || strings.Contains(bodyStr, sf.Signature)) {
				dedupHash := models.ComputeDedupHash(sf.Path, "SENSITIVE_FILE_EXPOSURE", models.CategoryInformationLeak)
				findings = append(findings, models.VulnerabilityFinding{
					ID:                uuid.New().String(),
					ScanID:            scanID,
					Title:             sf.Title,
					Description:       sf.Description,
					Remediation:       sf.Remediation,
					Category:          models.CategoryInformationLeak,
					Severity:          sf.Severity,
					CVSSScore:         sf.CVSS,
					CWE:               sf.CWE,
					OWASPCategory:     "A05:2021-Security Misconfiguration",
					TargetURL:         fileURL,
					AffectedParameter: sf.Path,
					InjectionContext:  "URL_PATH",
					DedupHash:         dedupHash,
					DiscoveredAt:      time.Now(),
					Proof: &models.HTTPProof{
						RequestURL:      fileURL,
						RequestMethod:   http.MethodGet,
						RequestHeaders:  sanitizer.MaskHeaders(req.Header),
						StatusCode:      resp.StatusCode,
						ResponseHeaders: sanitizer.MaskHeaders(resp.Header),
						ResponseBody:    sanitizer.MaskBody(string(bodySample)),
					},
				})
			}
		} else {
			resp.Body.Close()
		}
	}

	return findings
}
