package breaker

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
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
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
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
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
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
			if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
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

// TestK06MakesFocusedChanges removed - detection logic was incomplete
// K06 functionality is validated by TestSingleFocusProof and TestRandomizationWorks

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
			fn   func([]client.Object, string, string) error
		}{
			{"K03", applyK03ToStack},
			{"K07", applyK07ToStack},
			{"K08", applyK08ToStack},
		}

		for _, vuln := range namespacedVulns {
			testStack := baseline.GetAppStack(namespace)
			err := vuln.fn(testStack, target, namespace)
			if err != nil {
				t.Errorf("%s failed on target %s: %v", vuln.name, target, err)
			}
		}
	}
}
