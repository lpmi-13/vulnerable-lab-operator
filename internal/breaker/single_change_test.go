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
//
//nolint:gocyclo // Each block checks one isolated vulnerability condition; complexity is intentional
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

	// Check capabilities (sub-issue 2)
	origCaps := 0
	modCaps := 0
	if originalContainer.SecurityContext != nil && originalContainer.SecurityContext.Capabilities != nil {
		origCaps = len(originalContainer.SecurityContext.Capabilities.Add)
	}
	if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
		modCaps = len(container.SecurityContext.Capabilities.Add)
	}
	if origCaps != modCaps {
		changesCount++
	}

	// Check allowPrivilegeEscalation changed to true (sub-issue 3)
	origAPE := originalContainer.SecurityContext != nil && originalContainer.SecurityContext.AllowPrivilegeEscalation != nil && *originalContainer.SecurityContext.AllowPrivilegeEscalation
	modAPE := container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation
	if origAPE != modAPE {
		changesCount++
	}

	// Check readOnlyRootFilesystem disabled (sub-issue 4)
	origROFSFalse := originalContainer.SecurityContext != nil && originalContainer.SecurityContext.ReadOnlyRootFilesystem != nil && !*originalContainer.SecurityContext.ReadOnlyRootFilesystem
	modROFSFalse := container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil && !*container.SecurityContext.ReadOnlyRootFilesystem
	if origROFSFalse != modROFSFalse {
		changesCount++
	}

	// Check resource limits removed (sub-issue 5)
	if (len(originalContainer.Resources.Limits) > 0) != (len(container.Resources.Limits) > 0) {
		changesCount++
	}

	// Check hostPID/hostIPC enabled (sub-issue 6)
	if originalDep.Spec.Template.Spec.HostPID != modifiedDep.Spec.Template.Spec.HostPID ||
		originalDep.Spec.Template.Spec.HostIPC != modifiedDep.Spec.Template.Spec.HostIPC {
		changesCount++
	}

	// Check hostNetwork enabled (sub-issue 7)
	if originalDep.Spec.Template.Spec.HostNetwork != modifiedDep.Spec.Template.Spec.HostNetwork {
		changesCount++
	}

	// Check hostPath volume added (sub-issue 8)
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

//nolint:gocyclo // Test function needs to check multiple vulnerability types
func TestK06MakesFocusedChanges(t *testing.T) {
	namespace := "test-k06-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		// Find the original deployment state
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

		_, err := applyK06ToStack(&appStack, "api", namespace, nil, rng)
		if err != nil {
			t.Fatalf("applyK06ToStack failed: %v", err)
		}

		// Find the modified deployment
		var modifiedDep *appsv1.Deployment
		for _, obj := range appStack {
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
				modifiedDep = dep
				break
			}
		}

		if modifiedDep == nil {
			t.Fatal("Could not find api deployment after K06 application")
		}

		// Check that at least ONE K06 authentication vulnerability was applied
		vulnerabilityFound := false

		// Check 1: Service account name removed (default service account usage - K06:0)
		if modifiedDep.Spec.Template.Spec.ServiceAccountName == "" && originalDep.Spec.Template.Spec.ServiceAccountName != "" {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied default service account usage", i)
		}

		// Check 2: AutomountServiceAccountToken enabled (K06:1)
		if modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken != nil &&
			*modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken &&
			(originalDep.Spec.Template.Spec.AutomountServiceAccountToken == nil ||
				!*originalDep.Spec.Template.Spec.AutomountServiceAccountToken) {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied auto-mount service account token", i)
		}

		// Check 3: Permissive SA with automount (K06:2)
		// Check if unrestricted-sa was created and assigned
		if modifiedDep.Spec.Template.Spec.ServiceAccountName == unrestrictedSAName {
			// Verify the SA was added to the stack
			saFound := false
			for _, obj := range appStack {
				if sa, ok := obj.(*corev1.ServiceAccount); ok && sa.Name == unrestrictedSAName {
					if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
						saFound = true
						break
					}
				}
			}
			if saFound {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied permissive service account with automount", i)
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K06 iteration %d: No authentication vulnerability detected", i)
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

// detectK08VulnerabilityInDep checks for K08 vulnerabilities in an existing deployment
func detectK08VulnerabilityInDep(originalDep, modifiedDep *appsv1.Deployment) bool {
	origEnvs := originalDep.Spec.Template.Spec.Containers[0].Env
	modEnvs := modifiedDep.Spec.Template.Spec.Containers[0].Env

	// Check for hardcoded secrets replacing SecretKeyRef
	for j, modEnv := range modEnvs {
		if j < len(origEnvs) {
			origEnv := origEnvs[j]
			if origEnv.ValueFrom != nil && origEnv.ValueFrom.SecretKeyRef != nil && modEnv.ValueFrom == nil && modEnv.Value != "" {
				return true
			}
		}
	}

	// Check for hardcoded secrets appended as new env vars
	for j := len(origEnvs); j < len(modEnvs); j++ {
		if modEnvs[j].Value != "" && modEnvs[j].ValueFrom == nil {
			return true
		}
	}

	// Check for insecure volume permissions
	if hasInsecureVolumePermissions(modifiedDep.Spec.Template.Spec.Volumes) {
		return true
	}

	// Check for secrets in pod template annotations
	return hasSecretAnnotations(modifiedDep.Spec.Template.Annotations)
}

func TestK08MakesFocusedChanges(t *testing.T) {
	namespace := "test-k08-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

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

		if _, err := applyK08ToStack(&appStack, "api", namespace, nil, rng); err != nil {
			t.Fatalf("applyK08ToStack failed: %v", err)
		}

		vulnerabilityFound := false

		if len(appStack) > originalStackSize {
			vulnerabilityFound = true
			t.Logf("K08 iteration %d: Applied secrets in ConfigMap (added %d resources)", i, len(appStack)-originalStackSize)
		} else {
			modifiedDep := findDeployment(appStack)
			if modifiedDep == nil {
				t.Fatal("Could not find api deployment after K08 application")
			}
			if detectK08VulnerabilityInDep(originalDep, modifiedDep) {
				vulnerabilityFound = true
				t.Logf("K08 iteration %d: Applied deployment-level secrets vulnerability", i)
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K08 iteration %d: No secrets management vulnerability detected", i)
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
			name:     "subIssue 2: dangerous capabilities",
			subIssue: 2,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				container := &dep.Spec.Template.Spec.Containers[0]
				if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
					t.Fatal("expected Capabilities to be set")
				}
				caps := container.SecurityContext.Capabilities.Add
				hasSysAdmin := false
				hasNetAdmin := false
				for _, cap := range caps {
					if cap == "SYS_ADMIN" {
						hasSysAdmin = true
					}
					if cap == "NET_ADMIN" {
						hasNetAdmin = true
					}
				}
				if !hasSysAdmin || !hasNetAdmin {
					t.Errorf("expected Capabilities.Add to contain SYS_ADMIN and NET_ADMIN, got %v", caps)
				}
			},
		},
		{
			name:     "subIssue 3: allow privilege escalation",
			subIssue: 3,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				container := &dep.Spec.Template.Spec.Containers[0]
				if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || !*container.SecurityContext.AllowPrivilegeEscalation {
					t.Error("expected AllowPrivilegeEscalation == true")
				}
			},
		},
		{
			name:     "subIssue 6: hostPID and hostIPC",
			subIssue: 6,
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
			name:     "subIssue 7: hostNetwork",
			subIssue: 7,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if !dep.Spec.Template.Spec.HostNetwork {
					t.Error("expected HostNetwork == true")
				}
			},
		},
		{
			name:     "subIssue 8: hostPath volume",
			subIssue: 8,
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
			name:     "subIssue 0: namespace overpermissive",
			subIssue: 0,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-overpermissive", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-overpermissive-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-overpermissive'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-overpermissive-binding'")
				}
			},
		},
		{
			name:     "subIssue 1: default service account permissions",
			subIssue: 1,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-default-permissions", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-default-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-default-permissions'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-default-binding'")
				}
			},
		},
		{
			name:     "subIssue 2: excessive secrets access",
			subIssue: 2,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-secrets-reader", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-secrets-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-secrets-reader'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-secrets-binding'")
				}
			},
		},
		{
			name:     "subIssue 4: wildcard permissions",
			subIssue: 4,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-wildcard-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-wildcard-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-wildcard-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-wildcard-binding'")
				}
			},
		},
		{
			name:     "subIssue 5: exec and portforward",
			subIssue: 5,
			verify: func(t *testing.T, stack []client.Object, ns string) {
				foundRole := false
				foundBinding := false
				for _, obj := range stack {
					if role, ok := obj.(*rbacv1.Role); ok && role.Name == fmt.Sprintf("%s-exec-portforward-role", ns) {
						foundRole = true
					}
					if binding, ok := obj.(*rbacv1.RoleBinding); ok && binding.Name == fmt.Sprintf("%s-exec-portforward-binding", ns) {
						foundBinding = true
					}
				}
				if !foundRole {
					t.Error("expected Role with name '<ns>-exec-portforward-role'")
				}
				if !foundBinding {
					t.Error("expected RoleBinding with name '<ns>-exec-portforward-binding'")
				}
			},
		},
		{
			name:     "subIssue 6: delete capabilities",
			subIssue: 6,
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
			name:     "subIssue 7: pod creation",
			subIssue: 7,
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

func TestK06SubIssueSelection(t *testing.T) {
	tests := []struct {
		name     string
		subIssue int
		verify   func(*testing.T, []client.Object)
	}{
		{
			name:     "subIssue 0: default service account usage",
			subIssue: 0,
			verify: func(t *testing.T, appStack []client.Object) {
				dep := findDeployment(appStack)
				if dep == nil {
					t.Fatal("could not find api deployment")
				}
				if dep.Spec.Template.Spec.ServiceAccountName != "" {
					t.Errorf("expected ServiceAccountName == \"\", got %q", dep.Spec.Template.Spec.ServiceAccountName)
				}
			},
		},
		{
			name:     "subIssue 1: auto-mount service account token",
			subIssue: 1,
			verify: func(t *testing.T, appStack []client.Object) {
				dep := findDeployment(appStack)
				if dep == nil {
					t.Fatal("could not find api deployment")
				}
				if dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || !*dep.Spec.Template.Spec.AutomountServiceAccountToken {
					t.Error("expected AutomountServiceAccountToken == true")
				}
			},
		},
		{
			name:     "subIssue 2: permissive SA with automount",
			subIssue: 2,
			verify: func(t *testing.T, appStack []client.Object) {
				dep := findDeployment(appStack)
				if dep == nil {
					t.Fatal("could not find api deployment")
				}
				if dep.Spec.Template.Spec.ServiceAccountName != unrestrictedSAName {
					t.Errorf("expected ServiceAccountName == \"unrestricted-sa\", got %q", dep.Spec.Template.Spec.ServiceAccountName)
				}
				// Verify the SA was added to the stack
				saFound := false
				for _, obj := range appStack {
					if sa, ok := obj.(*corev1.ServiceAccount); ok && sa.Name == unrestrictedSAName {
						if sa.AutomountServiceAccountToken == nil || !*sa.AutomountServiceAccountToken {
							t.Error("expected SA AutomountServiceAccountToken == true")
						}
						saFound = true
						break
					}
				}
				if !saFound {
					t.Error("expected unrestricted-sa ServiceAccount in stack")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k06-deterministic"
			appStack := baseline.GetAppStack(namespace)

			_, err := applyK06ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK06ToStack failed: %v", err)
			}

			tt.verify(t, appStack)
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
			name:     "subIssue 0: no NetworkPolicy",
			subIssue: 0,
			verify: func(t *testing.T, stack []client.Object) {
				for _, obj := range stack {
					if _, ok := obj.(*networkingv1.NetworkPolicy); ok {
						t.Error("expected no NetworkPolicy in stack")
					}
				}
			},
		},
		{
			name:     "subIssue 1: data tier policies removed",
			subIssue: 1,
			verify: func(t *testing.T, stack []client.Object) {
				present := hasPolicies(t, stack)
				for _, name := range []string{"postgres-network-policy", "redis-network-policy"} {
					if present[name] {
						t.Errorf("expected NetworkPolicy %q to be removed from stack", name)
					}
				}
				if !present["api-network-policy"] {
					t.Error("expected api-network-policy to remain in stack")
				}
			},
		},
		{
			name:     "subIssue 2: user-service policy removed",
			subIssue: 2,
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
		{
			name:     "subIssue 3: monitoring tier policies removed",
			subIssue: 3,
			verify: func(t *testing.T, stack []client.Object) {
				present := hasPolicies(t, stack)
				for _, name := range []string{"prometheus-network-policy", "grafana-network-policy"} {
					if present[name] {
						t.Errorf("expected NetworkPolicy %q to be removed from stack", name)
					}
				}
				if !present["api-network-policy"] {
					t.Error("expected api-network-policy to remain in stack")
				}
			},
		},
		{
			name:     "subIssue 4: webapp policy removed",
			subIssue: 4,
			verify: func(t *testing.T, stack []client.Object) {
				present := hasPolicies(t, stack)
				if present["webapp-network-policy"] {
					t.Error("expected webapp-network-policy to be removed from stack")
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
		{
			name:     "subIssue 1: hardcoded secrets as env vars",
			subIssue: 1,
			verify: func(t *testing.T, stack []client.Object, dep *appsv1.Deployment) {
				container := &dep.Spec.Template.Spec.Containers[0]
				foundJWT := false
				foundAPIKey := false
				foundRedis := false
				for _, env := range container.Env {
					if env.Name == "JWT_SECRET" && env.Value != "" {
						foundJWT = true
					}
					if env.Name == "API_KEY" && env.Value != "" {
						foundAPIKey = true
					}
					if env.Name == "REDIS_PASSWORD" && env.Value != "" {
						foundRedis = true
					}
				}
				if !foundJWT || !foundAPIKey || !foundRedis {
					t.Error("expected container to have literal JWT_SECRET, API_KEY, and REDIS_PASSWORD env vars")
				}
			},
		},
		{
			name:     "subIssue 2: insecure volume permissions",
			subIssue: 2,
			verify: func(t *testing.T, stack []client.Object, dep *appsv1.Deployment) {
				foundInsecureVolume := false
				for _, volume := range dep.Spec.Template.Spec.Volumes {
					if volume.Secret != nil && volume.Secret.DefaultMode != nil {
						mode := *volume.Secret.DefaultMode
						if mode == 0644 {
							foundInsecureVolume = true
							break
						}
					}
				}
				if !foundInsecureVolume {
					t.Error("expected Secret volume with DefaultMode == 0644")
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

	// Test subIssue 9 (out of range for K01 which has 0-8)
	invalidSub = 9
	_, err = applyK01ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 9")
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

	// Test subIssue 8 (out of range for K03 which has 0-7)
	invalidSub = 8
	_, err = applyK03ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 8")
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

func TestK06SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k06-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	_, err := applyK06ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 3 (out of range for K06 which has 0-2)
	invalidSub = 3
	_, err = applyK06ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 3")
	}
}

func TestK06TargetNotFound(t *testing.T) {
	namespace := "test-k06-errors"
	appStack := baseline.GetAppStack(namespace)

	subIssue := 1
	_, err := applyK06ToStack(&appStack, "nonexistent-deployment", namespace, &subIssue, nil)
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

	// Test subIssue 5 (out of range for K07 which has 0-4)
	invalidSub = 5
	_, err = applyK07ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 5")
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

	// Test subIssue 4 (out of range for K08 which has 0-3)
	invalidSub = 4
	_, err = applyK08ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 4")
	}
}

func TestK08TargetNotFound(t *testing.T) {
	namespace := "test-k08-errors"
	appStack := baseline.GetAppStack(namespace)

	subIssue := 1 // Use subIssue 1 since it directly modifies the deployment
	_, err := applyK08ToStack(&appStack, "nonexistent-deployment", namespace, &subIssue, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
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
			{"K06", func(stack *[]client.Object, target, ns string) error {
				_, err := applyK06ToStack(stack, target, ns, nil, rng)
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
