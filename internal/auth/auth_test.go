package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAuth(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		err      error
		expected string
	}{
		{
			name:     "check key",
			key:      "ApiKey 12345",
			err:      nil,
			expected: "12345",
		},
		{
			name:     "normal key",
			key:      "ApiKey 12341fkhjalfy29fy10fh12",
			err:      nil,
			expected: "12341fkhjalfy29fy10fh12",
		},

		{
			name:     "header not include",
			key:      "",
			err:      ErrNoAuthHeaderIncluded,
			expected: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:     "malformed api key",
			key:      "12345",
			err:      errors.New("malformed authorization header"),
			expected: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			h.Add("Authorization", tt.key)

			result, err := GetAPIKey(h)
			if err != nil {
				if tt.err == nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if err.Error() != tt.err.Error() {
					t.Errorf("expected error '%s' got '%s'", tt.err.Error(), err.Error())
				}
				return
			}
			if result != tt.expected {
				t.Errorf("expected %s got %s", tt.expected, result)
			}
		})
	}
}
