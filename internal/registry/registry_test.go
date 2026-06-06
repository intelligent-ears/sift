package registry

import (
	"context"
	"testing"

	"github.com/sift-scanner/sift/pkg/module"
)

type mockModule struct {
	name string
}

func (m *mockModule) Name() string { return m.name }
func (m *mockModule) Consumes() []module.TaskType { return nil }
func (m *mockModule) Produces() []module.TaskType { return nil }
func (m *mockModule) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	return nil, nil, nil
}

func TestRegistry(t *testing.T) {
	// Reset registry for test isolation
	modules = nil

	tests := []struct {
		name     string
		toReg    module.Module
		expected int
	}{
		{
			name:     "register first module",
			toReg:    &mockModule{name: "mock1"},
			expected: 1,
		},
		{
			name:     "register second module",
			toReg:    &mockModule{name: "mock2"},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Register(tt.toReg)
			all := All()
			if len(all) != tt.expected {
				t.Errorf("expected %d registered modules, got %d", tt.expected, len(all))
			}
			if all[len(all)-1].Name() != tt.toReg.Name() {
				t.Errorf("expected last registered module name to be %q, got %q", tt.toReg.Name(), all[len(all)-1].Name())
			}
		})
	}
}
