package attack

import "sync"

// CleanupStatus records what the scanner knows about target-side cleanup.
type CleanupStatus string

const (
	CleanupNotAttempted CleanupStatus = "not_attempted"
	CleanupAttempted    CleanupStatus = "attempted"
	CleanupCompleted    CleanupStatus = "completed"
	CleanupUnavailable  CleanupStatus = "unavailable"
)

// TargetObject records an object a scan may have created on the target.
type TargetObject struct {
	Kind          string        `json:"kind"`
	Creation      string        `json:"creation"`
	ID            string        `json:"id,omitempty"`
	Name          string        `json:"name,omitempty"`
	ParentID      string        `json:"parent_id,omitempty"`
	Endpoint      string        `json:"endpoint,omitempty"`
	Cleanup       CleanupStatus `json:"cleanup"`
	CleanupDetail string        `json:"cleanup_detail,omitempty"`
}

// TargetState collects objects created by one rule execution.
type TargetState struct {
	mu      sync.Mutex
	objects []TargetObject
}

func (s *TargetState) Record(object TargetObject) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if object.Kind == "a2a_task" || object.Kind == "mcp_task" {
		for _, existing := range s.objects {
			if existing.Kind == object.Kind && existing.ID == object.ID && existing.Endpoint == object.Endpoint {
				return
			}
		}
	}
	s.objects = append(s.objects, object)
}

func (s *TargetState) Snapshot() []TargetObject {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TargetObject(nil), s.objects...)
}
