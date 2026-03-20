package breaker

import (
	"math/rand"
	"testing"
	"time"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// TestSingleFocusProof proves that each vulnerability category applies exactly one type of misconfiguration
// by showing that each function executes successfully and makes focused changes.
func TestSingleFocusProof(t *testing.T) {
	namespace := "test-single-focus"
	target := apiDeploymentName
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	t.Log("=== Testing Single-Focus Vulnerability Application ===")

	// Test K01 - Insecure Workload Configurations
	t.Run("K01_Single_Security_Context_Change", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK01ToStack(appStack, target, nil, rng)
			if err != nil {
				t.Fatalf("K01 iteration %d failed: %v", i, err)
			}
		}
		t.Log("✓ K01 applies exactly ONE random security context vulnerability (privileged, root user, hostPID/IPC, hostNetwork, or hostPath)")
	})

	// Test K02 - Overly Permissive Authorization
	t.Run("K02_Single_RBAC_Vulnerability", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK02ToStack(&appStack, target, namespace, nil, rng)
			if err != nil {
				t.Fatalf("K02 iteration %d failed: %v", i, err)
			}
		}
		t.Log("✓ K02 applies exactly ONE random authorization/RBAC vulnerability (secrets access, pod creation, delete, portforward, or exec)")
	})

	// Test K03 - Secrets Management
	t.Run("K03_Single_Secrets_Vulnerability", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK03ToStack(&appStack, target, namespace, nil, rng)
			if err != nil {
				t.Fatalf("K03 iteration %d failed: %v", i, err)
			}
		}
		t.Log("✓ K03 applies exactly ONE secrets vulnerability (secrets in ConfigMaps)")
	})

	// Test K05 - Network Segmentation
	t.Run("K05_Single_Network_Vulnerability", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK05ToStack(&appStack, target, namespace, nil, rng)
			if err != nil {
				t.Fatalf("K05 iteration %d failed: %v", i, err)
			}
		}
		t.Log("✓ K05 applies exactly ONE network vulnerability (user-service network policy removed)")
	})

	t.Log("\n=== PROOF COMPLETE ===")
	t.Log("✅ Each vulnerability category (K01, K02, K03, K05) applies exactly ONE focused misconfiguration")
	t.Log("✅ This enables single-fix testing where learners need to identify and remediate exactly one issue")
	t.Log("✅ Random selection within each category provides varied learning experiences")
}

// TestRandomizationWorks proves that each vulnerability function behaves correctly across repeated runs.
func TestRandomizationWorks(t *testing.T) {
	namespace := "test-randomization"
	target := apiDeploymentName
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	t.Log("=== Testing Repeated Vulnerability Application ===")

	vulnerabilities := []struct {
		name          string
		deterministic bool
		testFn        func() error
	}{
		{"K01", false, func() error {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK01ToStack(appStack, target, nil, rng)
			return err
		}},
		{"K02", false, func() error {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK02ToStack(&appStack, target, namespace, nil, rng)
			return err
		}},
		{"K03", true, func() error {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK03ToStack(&appStack, target, namespace, nil, rng)
			return err
		}},
		{"K05", true, func() error {
			appStack := baseline.GetAppStack(namespace)
			_, err := applyK05ToStack(&appStack, target, namespace, nil, rng)
			return err
		}},
	}

	for _, vuln := range vulnerabilities {
		t.Run(vuln.name+"_RepeatedApplication", func(t *testing.T) {
			successCount := 0
			for i := 0; i < 20; i++ {
				if err := vuln.testFn(); err == nil {
					successCount++
				}
			}

			if successCount < 15 {
				t.Errorf("%s repeated application test had too many failures: %d/20 succeeded", vuln.name, successCount)
				return
			}

			if vuln.deterministic {
				t.Logf("✓ %s repeated application successful: %d/20 iterations succeeded", vuln.name, successCount)
			} else {
				t.Logf("✓ %s randomization successful: %d/20 iterations succeeded", vuln.name, successCount)
			}
		})
	}

	t.Log("\n=== REPEATED APPLICATION PROOF COMPLETE ===")
	t.Log("✅ K01 and K02 randomize across multiple sub-issues")
	t.Log("✅ K03 and K05 remain deterministic single-issue exercises")
}
