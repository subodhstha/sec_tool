package payloads

import (
	"fmt"
	"strings"
	"sync"
)

// Registry is a thread-safe payload store that aggregates all payload families.
// It supports filtering by category, context, risk level, and target stack.
type Registry struct {
	mu      sync.RWMutex
	sets    map[PayloadCategory]PayloadSet
	allFlat []Payload
	loaded  bool
}

// NewRegistry creates and populates a payload registry with all built-in payload families.
func NewRegistry() *Registry {
	r := &Registry{
		sets: make(map[PayloadCategory]PayloadSet),
	}
	r.loadBuiltins()
	return r
}

// loadBuiltins registers every payload family into the registry.
func (r *Registry) loadBuiltins() {
	r.mu.Lock()
	defer r.mu.Unlock()

	families := []PayloadSet{
		// â”€â”€ Core Injection Families (existing) â”€â”€
		SQLiPayloads(),
		XSSPayloads(),
		CommandInjectionPayloads(),
		SSRFPayloads(),
		XXEPayloads(),
		PathTraversalPayloads(),
		SSTIPayloads(),
		CRLFAndHeaderPayloads(),
		OpenRedirectPayloads(),
		LDAPInjectionPayloads(),

		// â”€â”€ Extended Families (new â€” PayloadsAllTheThings coverage) â”€â”€
		NoSQLiPayloads(),
		CORSPayloads(),
		CSRFPayloads(),
		GraphQLPayloads(),
		JWTPayloads(),
		InsecureDeserializationPayloads(),
		PrototypePollutionPayloads(),
		IDORPayloads(),
		AuthBypassPayloads(),
		FileUploadPayloads(),
		FileInclusionPayloads(),
		WebSocketPayloads(),
		RaceConditionPayloads(),
	}

	for _, family := range families {
		r.sets[family.Category] = family
		r.allFlat = append(r.allFlat, family.Payloads...)
	}
	r.loaded = true
}

// RegisterCustomSet adds or merges a custom payload set at runtime.
func (r *Registry) RegisterCustomSet(set PayloadSet) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.sets[set.Category]; ok {
		knownIDs := make(map[string]struct{}, len(existing.Payloads))
		for _, payload := range existing.Payloads {
			if payload.ID != "" {
				knownIDs[payload.ID] = struct{}{}
			}
		}
		for _, payload := range set.Payloads {
			if payload.ID != "" {
				if _, exists := knownIDs[payload.ID]; exists {
					continue
				}
				knownIDs[payload.ID] = struct{}{}
			}
			existing.Payloads = append(existing.Payloads, payload)
		}
		r.sets[set.Category] = existing
	} else {
		r.sets[set.Category] = set
	}

	// Rebuild flat index
	r.allFlat = nil
	for _, s := range r.sets {
		r.allFlat = append(r.allFlat, s.Payloads...)
	}
}

// GetByCategory returns all payloads for a given vulnerability category.
func (r *Registry) GetByCategory(cat PayloadCategory) []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if set, ok := r.sets[cat]; ok {
		return set.Payloads
	}
	return nil
}

// GetByContext returns payloads effective in the given injection context.
func (r *Registry) GetByContext(ctx InjectionContext) []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Payload
	for _, p := range r.allFlat {
		for _, c := range p.Contexts {
			if c == ctx {
				result = append(result, p)
				break
			}
		}
	}
	return result
}

// GetSafePayloads returns only payloads marked as safe for production scanning.
func (r *Registry) GetSafePayloads() []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Payload
	for _, p := range r.allFlat {
		if p.SafeMode {
			result = append(result, p)
		}
	}
	return result
}

// GetActivePayloads returns payloads that require the active_fuzzing flag.
func (r *Registry) GetActivePayloads() []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Payload
	for _, p := range r.allFlat {
		if !p.SafeMode {
			result = append(result, p)
		}
	}
	return result
}

// FilterPayloads applies multiple filters to select matching payloads.
func (r *Registry) FilterPayloads(opts FilterOptions) []Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Payload
	for _, p := range r.allFlat {
		if matchesFilter(p, opts) {
			result = append(result, p)
		}
	}
	return result
}

// FilterOptions configures multi-dimensional payload selection.
type FilterOptions struct {
	Categories  []PayloadCategory  // Empty = all categories
	Contexts    []InjectionContext // Empty = all contexts
	SafeOnly    bool               // True = exclude non-safe payloads
	TargetStack []string           // Empty = all stacks; otherwise intersection
	Detection   []DetectionMethod  // Empty = all detection methods
}

func matchesFilter(p Payload, opts FilterOptions) bool {
	// Category filter
	if len(opts.Categories) > 0 {
		found := false
		for _, c := range opts.Categories {
			if p.Category == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Context filter
	if len(opts.Contexts) > 0 {
		found := false
		for _, ctx := range opts.Contexts {
			for _, pc := range p.Contexts {
				if pc == ctx {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Safe mode filter
	if opts.SafeOnly && !p.SafeMode {
		return false
	}

	// Target stack filter
	if len(opts.TargetStack) > 0 && len(p.TargetStack) > 0 {
		found := false
		for _, ts := range opts.TargetStack {
			for _, ps := range p.TargetStack {
				if strings.EqualFold(ts, ps) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// Detection method filter
	if len(opts.Detection) > 0 {
		found := false
		for _, d := range opts.Detection {
			if p.Detection == d {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Stats returns payload counts grouped by category.
func (r *Registry) Stats() map[PayloadCategory]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[PayloadCategory]int)
	for cat, set := range r.sets {
		stats[cat] = len(set.Payloads)
	}
	return stats
}

// TotalPayloads returns the total number of registered payloads.
func (r *Registry) TotalPayloads() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.allFlat)
}

// Categories returns all registered payload categories.
func (r *Registry) Categories() []PayloadCategory {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cats := make([]PayloadCategory, 0, len(r.sets))
	for cat := range r.sets {
		cats = append(cats, cat)
	}
	return cats
}

// Summary returns a human-readable summary string of the registry contents.
func (r *Registry) Summary() string {
	stats := r.Stats()
	total := r.TotalPayloads()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Vyomite DAST Payload Registry: %d total payloads\n", total))
	sb.WriteString("â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€\n")
	for cat, count := range stats {
		sb.WriteString(fmt.Sprintf("  %-25s %d payloads\n", cat, count))
	}
	return sb.String()
}
