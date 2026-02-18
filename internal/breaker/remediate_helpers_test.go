package breaker

import "testing"

// TestIsSecretData tests the isSecretData function with various scenarios
func TestIsSecretData(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  bool
	}{
		// Direct key matches
		{
			name:  "jwt-secret key with long value",
			key:   "jwt-secret",
			value: "my-jwt-secret-value",
			want:  true,
		},
		{
			name:  "redis-password key with long value",
			key:   "redis-password",
			value: "redis-pass-123",
			want:  true,
		},
		{
			name:  "database-url key with long value",
			key:   "database-url",
			value: "postgres://localhost:5432/db",
			want:  true,
		},
		{
			name:  "api-key key with long value",
			key:   "api-key",
			value: "sk_test_123456",
			want:  true,
		},
		// Partial key matches
		{
			name:  "key containing password",
			key:   "db-password-primary",
			value: "secretpass",
			want:  true,
		},
		{
			name:  "key containing secret",
			key:   "my-secret-key",
			value: "secretvalue",
			want:  true,
		},
		{
			name:  "key containing key",
			key:   "encryption-key",
			value: "encryptionkey123",
			want:  true,
		},
		{
			name:  "key containing token",
			key:   "auth-token",
			value: "tokenvalue",
			want:  true,
		},
		{
			name:  "key containing auth",
			key:   "auth-header",
			value: "bearer-token",
			want:  true,
		},
		// Case insensitivity
		{
			name:  "uppercase JWT-SECRET key",
			key:   "JWT-SECRET",
			value: "jwt-secret-value",
			want:  true,
		},
		// Rejection: short values (<=5)
		{
			name:  "secret key with value exactly 5 chars",
			key:   "secret",
			value: "12345",
			want:  false,
		},
		{
			name:  "password key with value exactly 4 chars",
			key:   "password",
			value: "1234",
			want:  false,
		},
		// Rejection: non-secret keys
		{
			name:  "hostname key with long value",
			key:   "hostname",
			value: "my-application-server",
			want:  false,
		},
		// Boundary: value exactly 5 chars (false) vs 6 chars (true)
		{
			name:  "secret key with exactly 5 chars",
			key:   "my-secret",
			value: "abcde",
			want:  false,
		},
		{
			name:  "secret key with exactly 6 chars",
			key:   "my-secret",
			value: "abcdef",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSecretData(tt.key, tt.value)
			if got != tt.want {
				t.Errorf("isSecretData(%q, %q) = %v, want %v", tt.key, tt.value, got, tt.want)
			}
		})
	}
}
