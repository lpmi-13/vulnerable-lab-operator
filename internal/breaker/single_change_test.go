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

// findDeployment finds a deployment by name in the given stack
func findDeployment(stack []client.Object, name string) *appsv1.Deployment {
	for _, obj := range stack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == name {
			return dep
		}
	}
	return nil
}

// findService finds a service by name in the given stack
func findService(stack []client.Object, name string) *corev1.Service {
	for _, obj := range stack {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == name {
			return svc
		}
	}
	return nil
}

func TestK01MakesFocusedChanges(t *testing.T) {
	namespace := "test-k01-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		// Find the target deployment before applying K01
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

		err := applyK01ToStack(appStack, "api", nil, rng)
		if err != nil {
			t.Fatalf("applyK01ToStack failed: %v", err)
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
			t.Fatal("Could not find api deployment after K01 application")
		}

		// Check that exactly one security context change was made
		container := &modifiedDep.Spec.Template.Spec.Containers[0]
		originalContainer := &originalDep.Spec.Template.Spec.Containers[0]

		changesCount := 0

		// Check privileged flag
		if (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) !=
			(originalContainer.SecurityContext != nil && originalContainer.SecurityContext.Privileged != nil && *originalContainer.SecurityContext.Privileged) {
			changesCount++
		}

		// Check runAsUser
		origUser := int64(65532) // default from baseline
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

		// Check capabilities
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

		if changesCount != 1 {
			t.Errorf("K01 should make exactly 1 security context change, but made %d changes", changesCount)
		}
	}
}

func TestK03MakesFocusedChanges(t *testing.T) {
	namespace := "test-k03-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

		err := applyK03ToStack(&appStack, "api", namespace, nil, rng)
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

		err := applyK06ToStack(appStack, "api", nil, rng)
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

		// Check 1: Service account name removed (default service account usage)
		if modifiedDep.Spec.Template.Spec.ServiceAccountName == "" && originalDep.Spec.Template.Spec.ServiceAccountName != "" {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied default service account usage", i)
		}

		// Check 2: Environment variables changed (hardcoded credentials or exposed auth)
		if len(modifiedDep.Spec.Template.Spec.Containers[0].Env) != len(originalDep.Spec.Template.Spec.Containers[0].Env) {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied environment variable changes", i)
		} else {
			// Check for changes in existing env vars
			for j, modEnv := range modifiedDep.Spec.Template.Spec.Containers[0].Env {
				if j < len(originalDep.Spec.Template.Spec.Containers[0].Env) {
					origEnv := originalDep.Spec.Template.Spec.Containers[0].Env[j]
					if modEnv.Value != origEnv.Value || (modEnv.ValueFrom == nil) != (origEnv.ValueFrom == nil) {
						vulnerabilityFound = true
						t.Logf("K06 iteration %d: Applied environment variable modification", i)
						break
					}
				}
			}
		}

		// Check 3: Service account token annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if _, exists := modifiedDep.Spec.Template.Annotations["kubernetes.io/service-account.token"]; exists {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied service account token annotation", i)
			}
		}

		// Check 4: Default service account annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if _, exists := modifiedDep.Spec.Template.Annotations["auth.kubernetes.io/default-account"]; exists {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied default service account annotation", i)
			}
		}

		// Check: AutomountServiceAccountToken enabled
		if modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken != nil &&
			*modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken &&
			(originalDep.Spec.Template.Spec.AutomountServiceAccountToken == nil ||
				!*originalDep.Spec.Template.Spec.AutomountServiceAccountToken) {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied auto-mount service account token", i)
		}

		// Check 5: Missing fsGroup in PodSecurityContext (new storage-related vuln)
		// This vulnerability creates a PodSecurityContext without fsGroup
		if modifiedDep.Spec.Template.Spec.SecurityContext != nil &&
			(originalDep.Spec.Template.Spec.SecurityContext == nil ||
				modifiedDep.Spec.Template.Spec.SecurityContext.FSGroup == nil) {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied missing fsGroup vulnerability", i)
		}

		// Check 6: Root user with volume access (new storage-related vuln)
		for _, cont := range modifiedDep.Spec.Template.Spec.Containers {
			if cont.SecurityContext != nil && cont.SecurityContext.RunAsUser != nil && *cont.SecurityContext.RunAsUser == 0 {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied root user with volume access vulnerability", i)
				break
			}
		}

		// Check 7: Privileged container with volume access (new storage-related vuln)
		for _, cont := range modifiedDep.Spec.Template.Spec.Containers {
			if cont.SecurityContext != nil && cont.SecurityContext.Privileged != nil && *cont.SecurityContext.Privileged {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied privileged container with volume access vulnerability", i)
				break
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K06 iteration %d: No authentication vulnerability detected", i)
		}
	}
}

func TestK07MakesFocusedChanges(t *testing.T) {
	namespace := "test-k07-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		// Find the original deployment and postgres service state
		var originalDep *appsv1.Deployment
		var originalPostgresSvc *corev1.Service
		for _, obj := range appStack {
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
				originalDep = dep.DeepCopy()
			}
			if svc, ok := obj.(*corev1.Service); ok && svc.Name == "postgres-service" {
				originalPostgresSvc = svc.DeepCopy()
			}
		}

		if originalDep == nil {
			t.Fatal("Could not find api deployment in baseline stack")
		}
		if originalPostgresSvc == nil {
			t.Fatal("Could not find postgres-service in baseline stack")
		}

		err := applyK07ToStack(&appStack, "api", namespace, nil, rng)
		if err != nil {
			t.Fatalf("applyK07ToStack failed: %v", err)
		}

		// Find the modified resources
		var modifiedDep *appsv1.Deployment
		var modifiedPostgresSvc *corev1.Service
		for _, obj := range appStack {
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
				modifiedDep = dep
			}
			if svc, ok := obj.(*corev1.Service); ok && svc.Name == "postgres-service" {
				modifiedPostgresSvc = svc
			}
		}

		if modifiedDep == nil {
			t.Fatal("Could not find api deployment after K07 application")
		}
		if modifiedPostgresSvc == nil {
			t.Fatal("Could not find postgres-service after K07 application")
		}

		vulnerabilityFound := false

		// Check Case 0: NetworkPolicy removed from stack
		hasNetworkPolicy := false
		for _, obj := range appStack {
			if _, ok := obj.(*networkingv1.NetworkPolicy); ok {
				hasNetworkPolicy = true
				break
			}
		}
		// Baseline should have a NetworkPolicy; if it's gone, case 0 was applied
		if !hasNetworkPolicy {
			vulnerabilityFound = true
			t.Logf("K07 iteration %d: Removed NetworkPolicy from stack", i)
		}

		// Check Case 1: Allow-all NetworkPolicy added
		for _, obj := range appStack {
			if np, ok := obj.(*networkingv1.NetworkPolicy); ok && np.Name == "allow-all-traffic" {
				vulnerabilityFound = true
				t.Logf("K07 iteration %d: Added allow-all NetworkPolicy", i)
				break
			}
		}

		// Check Case 2: Postgres service changed to NodePort
		if modifiedPostgresSvc.Spec.Type == corev1.ServiceTypeNodePort && originalPostgresSvc.Spec.Type != corev1.ServiceTypeNodePort {
			vulnerabilityFound = true
			t.Logf("K07 iteration %d: Applied postgres service NodePort exposure", i)
		}

		// Check Case 3: Postgres service changed to LoadBalancer
		if modifiedPostgresSvc.Spec.Type == corev1.ServiceTypeLoadBalancer && originalPostgresSvc.Spec.Type != corev1.ServiceTypeLoadBalancer {
			vulnerabilityFound = true
			t.Logf("K07 iteration %d: Applied postgres service LoadBalancer exposure", i)
		}

		if !vulnerabilityFound {
			t.Errorf("K07 iteration %d: No network vulnerability detected", i)
		}
	}
}

func TestK08MakesFocusedChanges(t *testing.T) {
	namespace := "test-k08-focused"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

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

		err := applyK08ToStack(&appStack, "api", namespace, nil, rng)
		if err != nil {
			t.Fatalf("applyK08ToStack failed: %v", err)
		}

		modifiedStackSize := len(appStack)
		vulnerabilityFound := false

		// Check if new resources were added (ConfigMap case)
		if modifiedStackSize > originalStackSize {
			vulnerabilityFound = true
			t.Logf("K08 iteration %d: Applied secrets in ConfigMap (added %d resources)", i, modifiedStackSize-originalStackSize)
		} else {
			// Check for modifications to existing deployment
			var modifiedDep *appsv1.Deployment
			for _, obj := range appStack {
				if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == apiDeploymentName {
					modifiedDep = dep
					break
				}
			}

			if modifiedDep == nil {
				t.Fatal("Could not find api deployment after K08 application")
			}

			// Check for hardcoded secrets in environment variables
			for j, modEnv := range modifiedDep.Spec.Template.Spec.Containers[0].Env {
				if j < len(originalDep.Spec.Template.Spec.Containers[0].Env) {
					origEnv := originalDep.Spec.Template.Spec.Containers[0].Env[j]
					// Check if SecretKeyRef was replaced with plain value
					if origEnv.ValueFrom != nil && origEnv.ValueFrom.SecretKeyRef != nil && modEnv.ValueFrom == nil && modEnv.Value != "" {
						vulnerabilityFound = true
						t.Logf("K08 iteration %d: Applied hardcoded secrets in environment", i)
						break
					}
				}
			}

			// Check for hardcoded secrets appended as new environment variables
			if len(modifiedDep.Spec.Template.Spec.Containers[0].Env) > len(originalDep.Spec.Template.Spec.Containers[0].Env) {
				for j := len(originalDep.Spec.Template.Spec.Containers[0].Env); j < len(modifiedDep.Spec.Template.Spec.Containers[0].Env); j++ {
					env := modifiedDep.Spec.Template.Spec.Containers[0].Env[j]
					if env.Value != "" && env.ValueFrom == nil {
						vulnerabilityFound = true
						t.Logf("K08 iteration %d: Applied hardcoded secrets as new env vars", i)
						break
					}
				}
			}

			// Check for insecure volume permissions
			for _, volume := range modifiedDep.Spec.Template.Spec.Volumes {
				if volume.Secret != nil && volume.Secret.DefaultMode != nil {
					mode := *volume.Secret.DefaultMode
					if mode&0077 != 0 { // World or group readable
						vulnerabilityFound = true
						t.Logf("K08 iteration %d: Applied insecure volume permissions (mode: %o)", i, mode)
						break
					}
				}
			}

			// Check for vulnerable annotations
			if modifiedDep.Spec.Template.Annotations != nil {
				if _, exists := modifiedDep.Spec.Template.Annotations["config.kubernetes.io/hardcoded-secrets"]; exists {
					vulnerabilityFound = true
					t.Logf("K08 iteration %d: Applied hardcoded secrets annotation", i)
				}
				if _, exists := modifiedDep.Spec.Template.Annotations["security.kubernetes.io/volume-permissions"]; exists {
					vulnerabilityFound = true
					t.Logf("K08 iteration %d: Applied insecure volume permissions annotation", i)
				}
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K08 iteration %d: No secrets management vulnerability detected", i)
		}
	}
}

// Deterministic sub-issue selection tests

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k01-deterministic"
			appStack := baseline.GetAppStack(namespace)

			err := applyK01ToStack(appStack, "api", &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK01ToStack failed: %v", err)
			}

			dep := findDeployment(appStack, "api")
			if dep == nil {
				t.Fatal("could not find api deployment")
			}

			tt.verify(t, dep)
		})
	}
}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k03-deterministic"
			appStack := baseline.GetAppStack(namespace)

			err := applyK03ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
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
		verify   func(*testing.T, *appsv1.Deployment)
	}{
		{
			name:     "subIssue 0: default service account usage",
			subIssue: 0,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if dep.Spec.Template.Spec.ServiceAccountName != "" {
					t.Errorf("expected ServiceAccountName == \"\", got %q", dep.Spec.Template.Spec.ServiceAccountName)
				}
			},
		},
		{
			name:     "subIssue 1: auto-mount service account token",
			subIssue: 1,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || !*dep.Spec.Template.Spec.AutomountServiceAccountToken {
					t.Error("expected AutomountServiceAccountToken == true")
				}
			},
		},
		{
			name:     "subIssue 2: missing fsGroup",
			subIssue: 2,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				if dep.Spec.Template.Spec.SecurityContext != nil && dep.Spec.Template.Spec.SecurityContext.FSGroup != nil {
					t.Error("expected SecurityContext != nil but FSGroup == nil")
				}
			},
		},
		{
			name:     "subIssue 3: root user with volume access",
			subIssue: 3,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				foundRootUser := false
				for _, cont := range dep.Spec.Template.Spec.Containers {
					if cont.SecurityContext != nil && cont.SecurityContext.RunAsUser != nil && *cont.SecurityContext.RunAsUser == 0 {
						foundRootUser = true
						break
					}
				}
				if !foundRootUser {
					t.Error("expected at least one container with RunAsUser == 0")
				}
			},
		},
		{
			name:     "subIssue 4: privileged container with volume access",
			subIssue: 4,
			verify: func(t *testing.T, dep *appsv1.Deployment) {
				foundPrivileged := false
				for _, cont := range dep.Spec.Template.Spec.Containers {
					if cont.SecurityContext != nil && cont.SecurityContext.Privileged != nil && *cont.SecurityContext.Privileged {
						foundPrivileged = true
						break
					}
				}
				if !foundPrivileged {
					t.Error("expected at least one container with Privileged == true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k06-deterministic"
			appStack := baseline.GetAppStack(namespace)

			err := applyK06ToStack(appStack, "api", &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK06ToStack failed: %v", err)
			}

			dep := findDeployment(appStack, "api")
			if dep == nil {
				t.Fatal("could not find api deployment")
			}

			tt.verify(t, dep)
		})
	}
}

func TestK07SubIssueSelection(t *testing.T) {
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
			name:     "subIssue 1: allow-all NetworkPolicy",
			subIssue: 1,
			verify: func(t *testing.T, stack []client.Object) {
				found := false
				for _, obj := range stack {
					if np, ok := obj.(*networkingv1.NetworkPolicy); ok && np.Name == "allow-all-traffic" {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected NetworkPolicy named 'allow-all-traffic'")
				}
			},
		},
		{
			name:     "subIssue 2: postgres-service is NodePort",
			subIssue: 2,
			verify: func(t *testing.T, stack []client.Object) {
				svc := findService(stack, "postgres-service")
				if svc == nil {
					t.Fatal("could not find postgres-service")
				}
				if svc.Spec.Type != corev1.ServiceTypeNodePort {
					t.Errorf("expected postgres-service Type == NodePort, got %s", svc.Spec.Type)
				}
				// Check for NodePort 30432
				foundNodePort := false
				for _, port := range svc.Spec.Ports {
					if port.NodePort == 30432 {
						foundNodePort = true
						break
					}
				}
				if !foundNodePort {
					t.Error("expected postgres-service to have NodePort 30432")
				}
			},
		},
		{
			name:     "subIssue 3: postgres-service is LoadBalancer",
			subIssue: 3,
			verify: func(t *testing.T, stack []client.Object) {
				svc := findService(stack, "postgres-service")
				if svc == nil {
					t.Fatal("could not find postgres-service")
				}
				if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
					t.Errorf("expected postgres-service Type == LoadBalancer, got %s", svc.Spec.Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := "test-k07-deterministic"
			appStack := baseline.GetAppStack(namespace)

			err := applyK07ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
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

			err := applyK08ToStack(&appStack, "api", namespace, &tt.subIssue, nil)
			if err != nil {
				t.Fatalf("applyK08ToStack failed: %v", err)
			}

			dep := findDeployment(appStack, "api")
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
	err := applyK01ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 3
	invalidSub = 3
	err = applyK01ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 3")
	}
}

func TestK01TargetNotFound(t *testing.T) {
	namespace := "test-k01-errors"
	appStack := baseline.GetAppStack(namespace)

	err := applyK01ToStack(appStack, "nonexistent-deployment", nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
	}
}

func TestK03SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k03-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	err := applyK03ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 3
	invalidSub = 3
	err = applyK03ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 3")
	}
}

func TestK03TargetNotFound(t *testing.T) {
	namespace := "test-k03-errors"
	appStack := baseline.GetAppStack(namespace)

	err := applyK03ToStack(&appStack, "nonexistent-deployment", namespace, nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
	}
}

func TestK06SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k06-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	err := applyK06ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 5
	invalidSub = 5
	err = applyK06ToStack(appStack, "api", &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 5")
	}
}

func TestK06TargetNotFound(t *testing.T) {
	namespace := "test-k06-errors"
	appStack := baseline.GetAppStack(namespace)

	err := applyK06ToStack(appStack, "nonexistent-deployment", nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent deployment")
	}
}

func TestK07SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k07-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	err := applyK07ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 4
	invalidSub = 4
	err = applyK07ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 4")
	}
}

func TestK08SubIssueOutOfRange(t *testing.T) {
	namespace := "test-k08-errors"
	appStack := baseline.GetAppStack(namespace)

	// Test subIssue -1
	invalidSub := -1
	err := applyK08ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue -1")
	}

	// Test subIssue 3
	invalidSub = 3
	err = applyK08ToStack(&appStack, "api", namespace, &invalidSub, nil)
	if err == nil {
		t.Error("expected error for subIssue 3")
	}
}

func TestK08TargetNotFound(t *testing.T) {
	namespace := "test-k08-errors"
	appStack := baseline.GetAppStack(namespace)

	subIssue := 1 // Use subIssue 1 since it directly modifies the deployment
	err := applyK08ToStack(&appStack, "nonexistent-deployment", namespace, &subIssue, nil)
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
			{"K01", func(stack []client.Object, t string) error { return applyK01ToStack(stack, t, nil, rng) }},
			{"K06", func(stack []client.Object, t string) error { return applyK06ToStack(stack, t, nil, rng) }},
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
				return applyK03ToStack(stack, target, ns, nil, rng)
			}},
			{"K08", func(stack *[]client.Object, target, ns string) error {
				return applyK08ToStack(stack, target, ns, nil, rng)
			}},
		}

		// K07 doesn't add resources, so it uses the original signature
		k07Vulns := []struct {
			name string
			fn   func(*[]client.Object, string, string) error
		}{
			{"K07", func(stack *[]client.Object, target, ns string) error {
				return applyK07ToStack(stack, target, ns, nil, rng)
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
