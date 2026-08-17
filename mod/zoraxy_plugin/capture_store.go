package zoraxy_plugin

import (
	"sync"
	"time"
)

const (
	captureShardCount = 64
	capturesPerShard  = 64
	captureTTL        = time.Minute
	maxRequestIDSize  = 128
)

type captureResult struct {
	status  int
	message string
	created time.Time
	expires time.Time
}

type captureShard struct {
	mu      sync.Mutex
	entries map[string]captureResult
}

type captureStore struct {
	shards [captureShardCount]captureShard
}

func newCaptureStore() *captureStore {
	store := &captureStore{}
	for i := range store.shards {
		store.shards[i].entries = make(map[string]captureResult, capturesPerShard)
	}
	return store
}

func (s *captureStore) put(id string, status int, message string) bool {
	if id == "" || len(id) > maxRequestIDSize {
		return false
	}
	now := time.Now()
	shard := s.shard(id)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for key, result := range shard.entries {
		if now.After(result.expires) {
			delete(shard.entries, key)
		}
	}
	if len(shard.entries) >= capturesPerShard {
		var oldestID string
		var oldest time.Time
		for key, result := range shard.entries {
			if oldestID == "" || result.created.Before(oldest) {
				oldestID, oldest = key, result.created
			}
		}
		delete(shard.entries, oldestID)
	}
	shard.entries[id] = captureResult{
		status:  status,
		message: message,
		created: now,
		expires: now.Add(captureTTL),
	}
	return true
}

func (s *captureStore) take(id string) (captureResult, bool) {
	if id == "" || len(id) > maxRequestIDSize {
		return captureResult{}, false
	}
	shard := s.shard(id)
	shard.mu.Lock()
	result, ok := shard.entries[id]
	delete(shard.entries, id)
	shard.mu.Unlock()
	if !ok || time.Now().After(result.expires) {
		return captureResult{}, false
	}
	return result, true
}

func (s *captureStore) shard(id string) *captureShard {
	var hash uint32 = 2166136261
	for i := 0; i < len(id); i++ {
		hash ^= uint32(id[i])
		hash *= 16777619
	}
	return &s.shards[hash&(captureShardCount-1)]
}
