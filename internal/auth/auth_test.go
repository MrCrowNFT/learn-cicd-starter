package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name: "Successful API key extraction",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-123"},
			},
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
		{
			name:          "Missing Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name: "Missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-api-key-123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Empty Authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: "no authorization header included", // Empty header is treated as missing
		},
		{
			name: "No space in Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKeytest-api-key-123"},
			},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name: "Multiple parts in Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-123 extra-part"},
			},
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check if the key matches the expected key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check error conditions
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.expectedError)
				} else if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing %q, got %q", tt.expectedError, err.Error())
				}
			}
		})
	}
}