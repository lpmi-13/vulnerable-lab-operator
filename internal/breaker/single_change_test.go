package breaker

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// These tests focus on proving that each vulnerability function makes focused, single changes
// rather than trying to count exact resource modifications (which can be complex due to slice manipulation)

func TestK01MakesFocusedChanges(t *testing.T) {
	namespace := "test-k01-focused"

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

		err := applyK01ToStack(appStack, "api")
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

func TestK02MakesFocusedChanges(t *testing.T) {
	namespace := "test-k02-focused"

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)

		// Find the target deployment before applying K02
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

		originalImage := originalDep.Spec.Template.Spec.Containers[0].Image

		err := applyK02ToStack(appStack, "api")
		if err != nil {
			t.Fatalf("applyK02ToStack failed: %v", err)
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
			t.Fatal("Could not find api deployment after K02 application")
		}

		modifiedImage := modifiedDep.Spec.Template.Spec.Containers[0].Image

		// Check that only the image was changed
		if originalImage == modifiedImage {
			t.Error("K02 should change the container image, but it remained the same")
		}

		// Verify it changed to one of the expected vulnerable images
		expectedImages := []string{"node:16-alpine"}
		found := false
		for _, expectedImage := range expectedImages {
			if modifiedImage == expectedImage {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("K02 should change image to a known vulnerable version, but got: %s", modifiedImage)
		}
	}
}

func TestK03MakesFocusedChanges(t *testing.T) {
	namespace := "test-k03-focused"

	for i := 0; i < 20; i++ {
		appStack := baseline.GetAppStack(namespace)
		originalStackSize := len(appStack)

		err := applyK03ToStack(&appStack, "api", namespace)
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

func TestK06MakesFocusedChanges(t *testing.T) {
	namespace := "test-k06-focused"

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

		err := applyK06ToStack(appStack, "api")
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

		// Check 1: Auto-mounted service account tokens
		if modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken != nil && *modifiedDep.Spec.Template.Spec.AutomountServiceAccountToken {
			if originalDep.Spec.Template.Spec.AutomountServiceAccountToken == nil || !*originalDep.Spec.Template.Spec.AutomountServiceAccountToken {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied auto-mount service account tokens", i)
			}
		}

		// Check 2: Service account name removed (default service account usage)
		if modifiedDep.Spec.Template.Spec.ServiceAccountName == "" && originalDep.Spec.Template.Spec.ServiceAccountName != "" {
			vulnerabilityFound = true
			t.Logf("K06 iteration %d: Applied default service account usage", i)
		}

		// Check 3: Environment variables changed (hardcoded credentials or exposed auth)
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

		// Check 4: Service account token annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if _, exists := modifiedDep.Spec.Template.Annotations["kubernetes.io/service-account.token"]; exists {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied service account token annotation", i)
			}
		}

		// Check 5: Default service account annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if _, exists := modifiedDep.Spec.Template.Annotations["auth.kubernetes.io/default-account"]; exists {
				vulnerabilityFound = true
				t.Logf("K06 iteration %d: Applied default service account annotation", i)
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K06 iteration %d: No authentication vulnerability detected", i)
		}
	}
}

func TestK07MakesFocusedChanges(t *testing.T) {
	namespace := "test-k07-focused"

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

		err := applyK07ToStack(appStack, "api", namespace)
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

		// Check Case 0: Network policy disabled annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if policy, exists := modifiedDep.Spec.Template.Annotations["networking.kubernetes.io/network-policy"]; exists && policy == "disabled" {
				vulnerabilityFound = true
				t.Logf("K07 iteration %d: Applied network policy disabled annotation", i)
			}
		}

		// Check Case 1: Network isolation disabled annotation
		if modifiedDep.Spec.Template.Annotations != nil {
			if isolation, exists := modifiedDep.Spec.Template.Annotations["networking.kubernetes.io/isolation"]; exists && isolation == "none" {
				vulnerabilityFound = true
				t.Logf("K07 iteration %d: Applied network isolation disabled annotation", i)
			}
		}

		// Check Case 2: Postgres service changed to NodePort
		if modifiedPostgresSvc.Spec.Type == corev1.ServiceTypeNodePort && originalPostgresSvc.Spec.Type != corev1.ServiceTypeNodePort {
			vulnerabilityFound = true
			t.Logf("K07 iteration %d: Applied postgres service NodePort exposure", i)
		}

		// Check Case 3: Service exposure annotation (but service type unchanged)
		if modifiedPostgresSvc.Annotations != nil && originalPostgresSvc.Spec.Type == modifiedPostgresSvc.Spec.Type {
			if exposure, exists := modifiedPostgresSvc.Annotations["networking.kubernetes.io/exposure"]; exists && exposure == "external-database-access" {
				vulnerabilityFound = true
				t.Logf("K07 iteration %d: Applied postgres service exposure annotation", i)
			}
		}

		if !vulnerabilityFound {
			t.Errorf("K07 iteration %d: No network vulnerability detected", i)
		}
	}
}

func TestK08MakesFocusedChanges(t *testing.T) {
	namespace := "test-k08-focused"

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

		err := applyK08ToStack(&appStack, "api", namespace)
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

func TestAllVulnerabilitiesApplySuccessfully(t *testing.T) {
	namespace := "test-success"
	targets := []string{"api", "webapp", "user-service"}

	for _, target := range targets {
		// Test each vulnerability type
		vulnerabilities := []struct {
			name string
			fn   func([]client.Object, string) error
		}{
			{"K01", func(stack []client.Object, t string) error { return applyK01ToStack(stack, t) }},
			{"K02", func(stack []client.Object, t string) error { return applyK02ToStack(stack, t) }},
			{"K06", func(stack []client.Object, t string) error { return applyK06ToStack(stack, t) }},
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
			{"K03", applyK03ToStack},
			{"K08", applyK08ToStack},
		}

		// K07 doesn't add resources, so it uses the original signature
		k07Vulns := []struct {
			name string
			fn   func([]client.Object, string, string) error
		}{
			{"K07", applyK07ToStack},
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
			err := vuln.fn(testStack, target, namespace)
			if err != nil {
				t.Errorf("%s failed on target %s: %v", vuln.name, target, err)
			}
		}
	}
}
