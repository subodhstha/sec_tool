package models

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ScanStore defines operations on scan records and vulnerability findings
type ScanStore interface {
	SaveScan(scan *ScanJob) error
	GetScan(id string) (*ScanJob, error)
	ListScans() []*ScanJob
	UpdateScanStatus(id string, status ScanStatus) error
	UpdateScanStats(id string, stats ScanStats) error
	UpdateScanFingerprint(id string, fp TargetFingerprint) error
	AddFinding(finding *VulnerabilityFinding) error
	GetFindingsByScanID(scanID string) []VulnerabilityFinding
}

// MemoryStore implements an in-memory thread-safe storage engine
type MemoryStore struct {
	mu       sync.RWMutex
	scans    map[string]*ScanJob
	findings map[string][]VulnerabilityFinding
}

var defaultStore *MemoryStore
var storeOnce sync.Once

// GetMemoryStore returns the shared memory storage instance
func GetMemoryStore() *MemoryStore {
	storeOnce.Do(func() {
		defaultStore = &MemoryStore{
			scans:    make(map[string]*ScanJob),
			findings: make(map[string][]VulnerabilityFinding),
		}
	})
	return defaultStore
}

func (s *MemoryStore) SaveScan(scan *ScanJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[scan.ID] = scan
	return nil
}

func (s *MemoryStore) GetScan(id string) (*ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scan, exists := s.scans[id]
	if !exists {
		return nil, fmt.Errorf("scan with ID '%s' not found", id)
	}
	return scan, nil
}

func (s *MemoryStore) ListScans() []*ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*ScanJob, 0, len(s.scans))
	for _, sc := range s.scans {
		list = append(list, sc)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

func (s *MemoryStore) UpdateScanStatus(id string, status ScanStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, exists := s.scans[id]
	if !exists {
		return fmt.Errorf("scan not found: %s", id)
	}
	scan.Status = status
	scan.UpdatedAt = time.Now()
	return nil
}

func (s *MemoryStore) UpdateScanStats(id string, stats ScanStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, exists := s.scans[id]
	if !exists {
		return fmt.Errorf("scan not found: %s", id)
	}
	scan.Stats = stats
	scan.UpdatedAt = time.Now()
	return nil
}

func (s *MemoryStore) UpdateScanFingerprint(id string, fp TargetFingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, exists := s.scans[id]
	if !exists {
		return fmt.Errorf("scan not found: %s", id)
	}
	scan.Fingerprint = fp
	scan.UpdatedAt = time.Now()
	return nil
}

func (s *MemoryStore) AddFinding(finding *VulnerabilityFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.findings[finding.ScanID]
	for i, f := range existing {
		// FR-5.1: If dedup hash matches, increment occurrence count instead of duplicate entry
		if f.DedupHash == finding.DedupHash {
			existing[i].OccurrencesCount++
			existing[i].RelatedURLs = append(existing[i].RelatedURLs, finding.TargetURL)
			return nil
		}
	}

	finding.OccurrencesCount = 1
	finding.RelatedURLs = []string{finding.TargetURL}
	s.findings[finding.ScanID] = append(s.findings[finding.ScanID], *finding)

	// Update findings count on scan job
	if scan, exists := s.scans[finding.ScanID]; exists {
		scan.Stats.VulnerabilitiesFound = len(s.findings[finding.ScanID])
	}

	return nil
}

func (s *MemoryStore) GetFindingsByScanID(scanID string) []VulnerabilityFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findings[scanID]
}
