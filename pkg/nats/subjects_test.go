package nats

import "testing"

func TestSubjects(t *testing.T) {
	tests := []struct {
		name     string
		function func() string
		expected string
	}{
		{
			name:     "SubjectTaskOpenPort 22",
			function: func() string { return SubjectTaskOpenPort(22) },
			expected: "sift.tasks.open_port.22",
		},
		{
			name:     "SubjectTaskOpenPort 80",
			function: func() string { return SubjectTaskOpenPort(80) },
			expected: "sift.tasks.open_port.80",
		},
		{
			name:     "SubjectTaskCMSContext wordpress",
			function: func() string { return SubjectTaskCMSContext("wordpress") },
			expected: "sift.tasks.cms_context.wordpress",
		},
		{
			name:     "SubjectTaskCMSContext joomla",
			function: func() string { return SubjectTaskCMSContext("joomla") },
			expected: "sift.tasks.cms_context.joomla",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.function()
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
