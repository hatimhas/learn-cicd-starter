// Package auth provides authentication utilities for API key extraction and validation.
package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		"valid header": {headers: http.Header{"Authorization": []string{"ApiKey abc123"}}, expectedKey: "abc123", expectedErr: nil},

		"missing header": {
			headers:     http.Header{},
			expectedKey: "", expectedErr: ErrNoAuthHeaderIncluded,
		},
		"malformed header(No token)": {
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "", expectedErr: ErrMalformedAuth,
		},
		"malformed header(Wrong scheme)": {
			headers: http.Header{"Authorization": []string{"Bearer abc123"}}, expectedKey: "",
			expectedErr: ErrMalformedAuth,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)
			diffKey := cmp.Diff(tc.expectedKey, got)

			if !errors.Is(err, tc.expectedErr) {
				t.Fatalf("expected error %v, got %v", tc.expectedErr, err)
			}

			if diffKey != "" {
				t.Fatalf("key mismatch:\n%s", diffKey)
			}
		})
	}
}
