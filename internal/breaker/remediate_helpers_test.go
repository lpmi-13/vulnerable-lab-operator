package breaker

import "testing"

// TestIsHardcodedSecret tests the isHardcodedSecret function with various scenarios
func TestIsHardcodedSecret(t *testing.T) {
	tests := []struct {
		name     string
		envName  string
		envValue string
		want     bool
	}{
		// Known pattern matches
		{
			name:     "JWT_SECRET with exact match",
			envName:  "JWT_SECRET",
			envValue: "super-secure-jwt-signing-key-2024",
			want:     true,
		},
		{
			name:     "REDIS_PASSWORD with exact match",
			envName:  "REDIS_PASSWORD",
			envValue: "redis-secure-password-123",
			want:     true,
		},
		{
			name:     "API_KEY with sk_test prefix",
			envName:  "API_KEY",
			envValue: "sk_test_12345",
			want:     true,
		},
		{
			name:     "API_KEY with sk_live prefix",
			envName:  "API_KEY",
			envValue: "sk_live_abcdefghijklmnop",
			want:     true,
		},
		// Generic detection: names containing "secret"/"password"/"key" with values >8 chars
		{
			name:     "generic secret name with long value",
			envName:  "MY_SECRET",
			envValue: "this-is-a-long-secret-value",
			want:     true,
		},
		{
			name:     "generic password name with long value",
			envName:  "DB_PASSWORD",
			envValue: "mypassword123",
			want:     true,
		},
		{
			name:     "generic key name with long value",
			envName:  "ENCRYPTION_KEY",
			envValue: "encryptionkey123456",
			want:     true,
		},
		// Rejection cases: short values (<=8)
		{
			name:     "secret name with short value (8 chars)",
			envName:  "MY_SECRET",
			envValue: "12345678",
			want:     false,
		},
		{
			name:     "secret name with short value (7 chars)",
			envName:  "MY_SECRET",
			envValue: "1234567",
			want:     false,
		},
		// Rejection cases: URL-like values (contain ":")
		{
			name:     "secret name with URL value",
			envName:  "DATABASE_SECRET",
			envValue: "postgresql://user:pass@host:5432/db",
			want:     false,
		},
		// Rejection cases: unrelated names
		{
			name:     "unrelated name with long value",
			envName:  "APP_NAME",
			envValue: "my-application-name",
			want:     false,
		},
		{
			name:     "unrelated name with short value",
			envName:  "PORT",
			envValue: "8080",
			want:     false,
		},
		// Boundary: value exactly 8 chars (false) vs 9 chars (true)
		{
			name:     "password with exactly 8 chars",
			envName:  "PASSWORD",
			envValue: "pass1234",
			want:     false,
		},
		{
			name:     "password with exactly 9 chars",
			envName:  "PASSWORD",
			envValue: "pass12345",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHardcodedSecret(tt.envName, tt.envValue)
			if got != tt.want {
				t.Errorf("isHardcodedSecret(%q, %q) = %v, want %v", tt.envName, tt.envValue, got, tt.want)
			}
		})
	}
}

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
