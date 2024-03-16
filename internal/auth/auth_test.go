package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case: valid Authorization header
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey my-api-key")
	key, err := GetAPIKey(headers)
	expectedKey := "my-api2-key"
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key != expectedKey {
		t.Errorf("Expected key %q, got %q", expectedKey, key)
	}

	// Test case: missing Authorization header
	headers = make(http.Header)
	key, err = GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
	if key != "" {
		t.Errorf("Expected empty key, got %q", key)
	}

	// Test case: malformed Authorization header
	headers = make(http.Header)
	headers.Set("Authorization", "Bearer token")
	key, err = GetAPIKey(headers)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if key != "" {
		t.Errorf("Expected empty key, got %q", key)
	}
}
