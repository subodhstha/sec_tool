package models

import (
	"context"
	"sync"
)

// Broker abstracts queue publishing for scan jobs and abort control signals
type Broker interface {
	PublishScanJob(ctx context.Context, job *ScanJob) error
	PublishAbortSignal(ctx context.Context, scanID string) error
	SubscribeScanJobs() (<-chan *ScanJob, error)
	SubscribeAbortSignals() (<-chan string, error)
}

// MemoryBroker provides an in-memory thread-safe broker channel implementation
type MemoryBroker struct {
	mu          sync.RWMutex
	jobChan     chan *ScanJob
	subscribers []chan string
}

var defaultBroker *MemoryBroker
var brokerOnce sync.Once

// GetMemoryBroker returns the shared singleton broker
func GetMemoryBroker() *MemoryBroker {
	brokerOnce.Do(func() {
		defaultBroker = &MemoryBroker{
			jobChan:     make(chan *ScanJob, 1000),
			subscribers: make([]chan string, 0),
		}
	})
	return defaultBroker
}

func (b *MemoryBroker) PublishScanJob(ctx context.Context, job *ScanJob) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case b.jobChan <- job:
		return nil
	}
}

func (b *MemoryBroker) PublishAbortSignal(ctx context.Context, scanID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, ch := range b.subscribers {
		select {
		case ch <- scanID:
		default:
		}
	}
	return nil
}

func (b *MemoryBroker) SubscribeScanJobs() (<-chan *ScanJob, error) {
	return b.jobChan, nil
}

func (b *MemoryBroker) SubscribeAbortSignals() (<-chan string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan string, 50)
	b.subscribers = append(b.subscribers, ch)
	return ch, nil
}
