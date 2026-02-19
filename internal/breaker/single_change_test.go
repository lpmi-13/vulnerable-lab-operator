package breaker

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// These tests focus on proving that each vulnerability function makes focused, single changes
// rather than trying to count exact resource modifications (which can be complex due to slice manipulation)

// Helper functions for finding resources in stacks

// findDeployment finds the api deployment in the given stack
func findDeployment(stack []client.Object) *appsv1.Deployment {
	for _, obj := range stack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
			return dep
		}
	}
	return nil
}

// countK01Changes counts the number of K01-relevant workload configuration changes
func countK01Changes(originalDep, modifiedDep *appsv1.Deployment) int {
	container := &modifiedDep.Spec.Template.Spec.Containers[0]
	originalContainer := &originalDep.Spec.Template.Spec.Containers[0]
	changesCount := 0

	// Check privileged flag (sub-issue 0)
	origPriv := originalContainer.SecurityContext != nil && originalContainer.SecurityContext.Privileged != nil && *originalContainer.SecurityContext.Privileged
	modPriv := container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged
	if origPriv != modPriv {
		changesCount++
	}

	// Check runAsUser (sub-issue 1)
	origUser := int64(65532)
	if originalContainer.SecurityContext != nil && originalContainer.SecurityContext.RunAsUser != nil {
		origUser = *originalContainer.SecurityContext.RunAsUser
	}
	modUser := origUser
	if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil {
		modUser = *container.SecurityContext.RunAsUser
	}
	if origUser != modUser {
		changesCount++
	}

	// Check hostPID/hostIPC enabled (sub-issue 2)
	if originalDep.Spec.Template.Spec.HostPID != modifiedDep.Spec.Template.Spec.HostPID ||
		originalDep.Spec.Template.Spec.HostIPC != modifiedDep.Spec.Template.Spec.HostIPC {
		changesCount++
	}

	// Check hostNetwork enabled (sub-issue 3)
	if originalDep.Spec.Template.Spec.HostNetwork != modifiedDep.Spec.Template.Spec.HostNetwork {
		changesCount++
	}

	// Check hostPath volume added (sub-issue 4)
	origHostPath := false
	for _, v := range originalDep.Spec.Template.Spec.Volumes {
		if v.HostPath != nil {
			origHostPath = true
			break
		}
	}
	modHostPath := false
	for _, v := range modifiedDep.Spec.Template.Spec.Volumes {
		if v.HostPath != nil {
			modHostPath = true
			break
		}
	}
	if origHostPath != modHostPath {
		changesCount++
	}

	return changesCount
}

func TestK01MakesFocusedChanges(t *testing.T) {
	namespace := "test-k01-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		var originalDep *appsv1.Deployment
		for _, obj := range appStack {
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
				originalDep = dep.DeepCopy()
				break
			}
		}
		if originalDep == nil {
			t.Fatal("Could not find api deployment in baseline stack")
		}

		if _, err := applyK01ToStack(appStack, "api", nil, rng); err != nil {
			t.Fatalf("applyK01ToStack failed: %v", err)
		}

		modifiedDep := findDeployment(appStack)
		if modifiedDep == nil {
			t.Fatal("Could not find api deployment after K01 application")
		}

		if changesCount := countK01Changes(originalDep, modifiedDep); changesCount != 1 {
			t.Errorf("K01 should make exactly 1 workload configuration change, but made %d changes", changesCount)
		}
	}
}

func TestK03MakesFocusedChanges(t *testing.T) {
	namespace := "test-k03-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

		_, err := applyK03ToStack(&appStack, "api", namespace, nil, rng)
		if err != nil {
			t.Fatalf("applyK03ToStack failed: %v", err)
		}

		modifiedStackSize := len(appStack)

		// K03 should add new RBAC resources (1 or 2 depending on the vulnerability type)
		if modifiedStackSize <= originalStackSize {
			t.Errorf("K03 should add RBAC resources but stack size didn't increase: original=%d, modified=%d", originalStackSize, modifiedStackSize)
			continue
		}

		addedResources := modifiedStackSize - originalStackSize
		if addedResources < 1 || addedResources > 2 {
			t.Errorf("K03 should add 1-2 RBAC resources, but added %d", addedResources)
			continue
		}

		// Verify that new resources are RBAC related
		foundRBACResource := false
		for j := originalStackSize; j < modifiedStackSize; j++ {
			switch appStack[j].(type) {
			case *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding, *rbacv1.Role, *rbacv1.RoleBinding:
				foundRBACResource = true
			default:
				t.Errorf("K03 added non-RBAC resource: %T", appStack[j])
			}
		}

		if !foundRBACResource {
			t.Errorf("K03 should add RBAC resources but none found")
		}
	}
}

// detectK07NetworkPolicyVulnerability checks for K07 network policy related vulnerabilities
func detectK07NetworkPolicyVulnerability(appStack []client.Object) (bool, string) {
	allPolicies := []string{
		"api-network-policy",
		"postgres-network-policy",
		"redis-network-policy",
		"user-service-network-policy",
		"prometheus-network-policy",
		"grafana-network-policy",
		"webapp-network-policy",
	}
	presentPolicies := make(map[string]struct{})
	for _, obj := range appStack {
		if np, ok := obj.(*networkingv1.NetworkPolicy); ok {
			presentPolicies[np.Name] = struct{}{}
		}
	}
	for _, name := range allPolicies {
		if _, exists := presentPolicies[name]; !exists {
			return true, "Removed NetworkPolicy from stack: " + name
		}
	}
	return false, ""
}

func TestK07MakesFocusedChanges(t *testing.T) {
	namespace := "test-k07-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		if _, err := applyK07ToStack(&appStack, "api", namespace, nil, rng); err != nil {
			t.Fatalf("applyK07ToStack failed: %v", err)
		}

		if found, msg := detectK07NetworkPolicyVulnerability(appStack); !found {
			t.Errorf("K07 iteration %d: No network vulnerability detected", i)
		} else {
			t.Logf("K07 iteration %d: %s", i, msg)
		}
	}
}

func TestK08MakesFocusedChanges(t *testing.T) {
	namespace := "test-k08-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

		if _, err := applyK08ToStack(&appStack, "api", namespace, nil, rng); err != nil {
			t.Fatalf("applyK08ToStack failed: %v", err)
		}

		if len(appStack) <= originalStackSize {
			t.Errorf("K08 iteration %d: Expected ConfigMap to be added to stack", i)
		} else {
			t.Logf("K08 iteration %d: Applied secrets in ConfigMap (added %d resources)", i, len(appStack)-originalStackSize)
		}
	}
}

// Deterministic sub-issue selection tests

//nolint:gocyclo // Test function needs to check multiple vulnerability types
func TestK01SubIssueSelection(t *testing.T) {
	tests := []struct {
		name     string
		subIssue int
		verify   func(*testing.T, *appsv1.Deployment)
	}{
		{
			name:     "subIssue 0: privileged container",
			subIssue: 0,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				container := &dep.Spec.Template.Spec.Containers[0]
				if container.SecurityContext == nil || container.SecurityContext.Privileged == nil || !*container.SecurityContext.Privileged {
					t.Error("expected Privileged == true")
				}
				if dep.Spec.Template.Annotations["container.security.privileged"] == "" {
					t.Error("expected annotation 'container.security.privileged' present")
				}
			},
		},
		{
			name:     "subIssue 1: running as root",
			subIssue: 1,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				container := &dep.Spec.Template.Spec.Containers[0]
				if container.SecurityContext == nil || container.SecurityContext.RunAsUser == nil || *container.SecurityContext.RunAsUser != 0 {
					t.Error("expected RunAsUser == 0")
				}
				if container.SecurityContext.RunAsNonRoot == nil || *container.SecurityContext.RunAsNonRoot {
					t.Error("expected RunAsNonRoot == false")
				}
			},
		},
		{
			name:     "subIssue 2: hostPID and hostIPC",
			subIssue: 2,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if !dep.Spec.Template.Spec.HostPID {
					t.Error("expected HostPID == true")
				}
				if !dep.Spec.Template.Spec.HostIPC {
					t.Error("expected HostIPC == true")
				}
			},
		},
		{
			name:     "subIssue 3: hostNetwork",
			subIssue: 3,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if !dep.Spec.Template.Spec.HostNetwork {
					t.Error("expected HostNetwork == true")
				}
			},
		},
		{
			name:     "subIssue 4: hostPath volume",
			subIssue: 4,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				foundHostPath := false
				for _, vol := range dep.Spec.Template.Spec.Volumes {
					if vol.HostPath != nil && vol.HostPath.Path == "/var/log" {
						foundHostPath = true
						break
					}
				}
				if !foundHostPath {
					t.Error("expected hostPath volume with path /var/log")
				}
				foundMount := false
				for _, vm := range dep.Spec.Template.Spec.Containers[0].VolumeMounts {
					if vm.Name == "host-data" && vm.MountPath == "/host-log" {
						foundMount = true
						break
					}
				}
				if !foundMount {
					t.Error("expected volumeMount 'host-data' at /host-log")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k01-deterministic"
			appStack := baseline.GetAppStack(namespace)

			_, err := applyK01ToStack(appStack, "api", &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK01ToStack failed: %v", err)
			}

			dep := findDeployment(appStack)
			if dep == nil {
				t.Fatal("could not find api deployment")
			}

			tt.verify(t, dep)
		})
	}
}

//nolint:gocyclo // Test function needs to check multiple vulnerability types
func TestK03SubIssueSelection(t *testing.T) {
	tests := []struct {
		name     string
		subIssue int
		verify   func(*testing.T, []client.Object, string)
	}{
		{
			name:     "subIssue 0: secrets access (C-0015)",
			subIssue: 0,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-secrets-access-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-secrets-access-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-secrets-access-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-secrets-access-binding'")
				}
			},
		},
		{
			name:     "subIssue 1: pod creation (C-0188)",
			subIssue: 1,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-pod-create-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-pod-create-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-pod-create-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-pod-create-binding'")
				}
			},
		},
		{
			name:     "subIssue 2: delete capabilities (C-0007)",
			subIssue: 2,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-delete-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-delete-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-delete-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-delete-binding'")
				}
			},
		},
		{
			name:     "subIssue 3: portforward privileges (C-0063)",
			subIssue: 3,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-portforward-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-portforward-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-portforward-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-portforward-binding'")
				}
			},
		},
		{
			name:     "subIssue 4: command execution (C-0002)",
			subIssue: 4,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-exec-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-exec-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-exec-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-exec-binding'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k03-deterministic"
			appStack := baseline.GetAppStack(namespace)

			_, err := applyK03ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK03ToStack failed: %v", err)
			}

			tt.verify(t, appStack, namespace)
		})
	}
}

func TestK07SubIssueSelection(t *testing.T) {
	hasPolicies := func(t *testing.T, stack []client.Object) map[string]bool {
		t.Helper()
		present := make(map[string]bool)
		for _, obj := range stack {
			if np, ok := obj.(*networkingv1.NetworkPolicy); ok {
				present[np.Name] = true
			}
		}
		return present
	}

	tests := []struct {
		name     string
		subIssue int
		verify   func(*testing.T, []client.Object)
	}{
		{
			name:     "subIssue 0: user-service policy removed",
			subIssue: 0,
			verify: func(t *testing.T, stack []client.Object) {
				present := hasPolicies(t, stack)
				if present["user-service-network-policy"] {
					t.Error("expected user-service-network-policy to be removed from stack")
				}
				if !present["api-network-policy"] {
					t.Error("expected api-network-policy to remain in stack")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k07-deterministic"
			appStack := baseline.GetAppStack(namespace)

			_, err := applyK07ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK07ToStack failed: %v", err)
			}

			tt.verify(t, appStack)
		})
	}
}

func TestK08SubIssueSelection(t *testing.T) {
	tests := []struct {
		name     string
		subIssue int
		verify   func(*testing.T, []client.Object, *appsv1.Deployment)
	}{
		{
			name:     "subIssue 0: secrets in ConfigMap",
			subIssue: 0,
			verify: func(t *testing.T, stack []client.Object, dep *appsv1.Deployment) {
				foundConfigMap := false
				for _, obj := range stack {
					if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Name == "api-config" {
						foundConfigMap = true
						// Check for secret data keys
						if _, ok := cm.Data["jwt-secret"]; !ok {
							t.Error("expected ConfigMap to contain 'jwt-secret' key")
						}
					}
				}
				if !foundConfigMap {
					t.Error("expected ConfigMap named 'api-config'")
				}
				// Check that deployment envs reference the ConfigMap
				container := &dep.Spec.Template.Spec.Containers[0]
				foundConfigEnv := false
				for _, env := range container.Env {
					if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
						foundConfigEnv = true
						break
					}
				}
				if !foundConfigEnv {
					t.Error("expected deployment to reference ConfigMap in env vars")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k08-deterministic"
			appStack := baseline.GetAppStack(namespace)

			_, err := applyK08ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK08ToStack failed: %v", err)
			}

			dep := findDeployment(appStack)
			if dep == nil {
				t.Fatal("could not find api deployment")
			}

			tt.verify(t, appStack, dep)
		})
	}
}

// Error-case tests

func TestK01SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k01-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	_, err := applyK01ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 5 (out of range for K01 which has 0-4)
	invalidSub = 5
	_, err = applyK01ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 5")
	}
}

func TestK01TargetNotFound(t *testing.T) {
	namespace := "test-k01-errors"
	appStack := baseline.GetAppStack(namespace)

	_, err := applyK01ToStack(appStack, "nonexistent-deployment", nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
	}
}

func TestK03SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k03-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	_, err := applyK03ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 7 (out of range for K03 which has 0-6)
	invalidSub = 7
	_, err = applyK03ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 7")
	}
}

func TestK03TargetNotFound(t *testing.T) {
	namespace := "test-k03-errors"
	appStack := baseline.GetAppStack(namespace)

	_, err := applyK03ToStack(&appStack, "nonexistent-deployment", namespace, nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
	}
}

func TestK07SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k07-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	_, err := applyK07ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 1 (out of range for K07 which has only 0)
	invalidSub = 1
	_, err = applyK07ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 1")
	}
}

func TestK08SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k08-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	_, err := applyK08ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 1 (out of range for K08 which has only 0)
	invalidSub = 1
	_, err = applyK08ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 1")
	}
}

func TestAllVulnerabilitiesApplySuccessfully(t *testing.T) {
	namespace := "test-success"
	targets := []string{"api", "webapp", "user-service"}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, target := range targets {
		// Test each vulnerability type
		vulnerabilities := []struct {
			name string
			fn   func([]client.Object, string) error
		}{
			{"K01", func(stack []client.Object, t string) error { _, err := applyK01ToStack(stack, t, nil, rng); return err }},
		}

		for _, vuln := range vulnerabilities {
			testStack := baseline.GetAppStack(namespace)
			err := vuln.fn(testStack, target)
			if err != nil {
				t.Errorf("%s failed on target %s: %v", vuln.name, target, err)
			}
		}

		// Test vulnerabilities that need namespace parameter
		namespacedVulns := []struct {
			name string
			fn   func(*[]client.Object, string, string) error
		}{
			{"K03", func(stack *[]client.Object, target, ns string) error {
				_, err := applyK03ToStack(stack, target, ns, nil, rng)
				return err
			}},
			{"K08", func(stack *[]client.Object, target, ns string) error {
				_, err := applyK08ToStack(stack, target, ns, nil, rng)
				return err
			}},
		}

		// K07 doesn't add resources, so it uses the original signature
		k07Vulns := []struct {
			name string
			fn   func(*[]client.Object, string, string) error
		}{
			{"K07", func(stack *[]client.Object, target, ns string) error {
				_, err := applyK07ToStack(stack, target, ns, nil, rng)
				return err
			}},
		}

		for _, vuln := range namespacedVulns {
			testStack := baseline.GetAppStack(namespace)
			err := vuln.fn(&testStack, target, namespace)
			if err != nil {
				t.Errorf("%s failed on target %s: %v", vuln.name, target, err)
			}
		}

		for _, vuln := range k07Vulns {
			testStack := baseline.GetAppStack(namespace)
			err := vuln.fn(&testStack, target, namespace)
			if err != nil {
				t.Errorf("%s failed on target %s: %v", vuln.name, target, err)
			}
		}
	}
}
