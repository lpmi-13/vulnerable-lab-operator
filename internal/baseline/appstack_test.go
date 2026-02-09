package baseline

import (
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const testNamespace = "test-namespace"

func TestGetAppStackReturnsNonEmpty(t *testing.T) {
	stack := GetAppStack(testNamespace)
	if stack == nil {
		t.Fatal("GetAppStack returned nil")
	}
	if len(stack) == 0 {
		t.Fatal("GetAppStack returned empty slice")
	}
}

func TestGetAppStackNamespaceConsistency(t *testing.T) {
	namespace := testNamespace
	stack := GetAppStack(namespace)

	for _, obj := range stack {
		// Only check objects that are namespaced
		if obj.GetNamespace() != "" && obj.GetNamespace() != namespace {
			t.Errorf("object %s has namespace %s, expected %s", obj.GetName(), obj.GetNamespace(), namespace)
		}
	}
}

func TestGetAppStackContainsExpectedDeployments(t *testing.T) {
	namespace := testNamespace
	stack := GetAppStack(namespace)

	expectedDeployments := []string{
		"postgres-db",
		"redis-cache",
		"prometheus",
		"grafana",
		"api",
		"user-service",
		"payment-service",
		"webapp",
	}

	foundDeployments := make(map[string]bool)
	for _, obj := range stack {
		if dep, ok := obj.(*appsv1.Deployment); ok {
			foundDeployments[dep.Name] = true
		}
	}

	for _, expectedName := range expectedDeployments {
		if !foundDeployments[expectedName] {
			t.Errorf("expected deployment %s not found in stack", expectedName)
		}
	}

	if len(foundDeployments) != len(expectedDeployments) {
		t.Errorf("expected %d deployments, found %d", len(expectedDeployments), len(foundDeployments))
	}
}

func TestGetAppStackDeploymentsHaveSecureDefaults(t *testing.T) {
	namespace := testNamespace
	stack := GetAppStack(namespace)

	for _, obj := range stack {
		dep, ok := obj.(*appsv1.Deployment)
		if !ok {
			continue
		}

		// Check ServiceAccountName
		if dep.Spec.Template.Spec.ServiceAccountName != "restricted-sa" {
			t.Errorf("deployment %s: expected ServiceAccountName == \"restricted-sa\", got %q",
				dep.Name, dep.Spec.Template.Spec.ServiceAccountName)
		}

		// Check for at least one container
		if len(dep.Spec.Template.Spec.Containers) == 0 {
			t.Errorf("deployment %s has no containers", dep.Name)
			continue
		}

		// Check first container's security context
		container := dep.Spec.Template.Spec.Containers[0]
		if container.SecurityContext == nil {
			t.Errorf("deployment %s: container %s has nil SecurityContext", dep.Name, container.Name)
			continue
		}

		secCtx := container.SecurityContext

		// Check RunAsNonRoot
		if secCtx.RunAsNonRoot == nil || !*secCtx.RunAsNonRoot {
			t.Errorf("deployment %s: expected RunAsNonRoot == true", dep.Name)
		}

		// Check AllowPrivilegeEscalation
		if secCtx.AllowPrivilegeEscalation == nil || *secCtx.AllowPrivilegeEscalation {
			t.Errorf("deployment %s: expected AllowPrivilegeEscalation == false", dep.Name)
		}

		// Check ReadOnlyRootFilesystem
		if secCtx.ReadOnlyRootFilesystem == nil || !*secCtx.ReadOnlyRootFilesystem {
			t.Errorf("deployment %s: expected ReadOnlyRootFilesystem == true", dep.Name)
		}

		// Check Capabilities.Drop contains "ALL"
		if secCtx.Capabilities == nil {
			t.Errorf("deployment %s: Capabilities is nil", dep.Name)
			continue
		}
		hasDropAll := false
		for _, cap := range secCtx.Capabilities.Drop {
			if cap == "ALL" {
				hasDropAll = true
				break
			}
		}
		if !hasDropAll {
			t.Errorf("deployment %s: expected Capabilities.Drop to contain \"ALL\"", dep.Name)
		}
	}
}

func TestGetAppStackIdempotent(t *testing.T) {
	namespace := testNamespace
	stack1 := GetAppStack(namespace)
	stack2 := GetAppStack(namespace)

	if len(stack1) != len(stack2) {
		t.Fatalf("stacks have different lengths: %d vs %d", len(stack1), len(stack2))
	}

	// Verify the stacks are structurally identical
	for i := range stack1 {
		obj1 := stack1[i]
		obj2 := stack2[i]

		// Check types match
		if reflect.TypeOf(obj1) != reflect.TypeOf(obj2) {
			t.Errorf("stack[%d]: types differ: %T vs %T", i, obj1, obj2)
			continue
		}

		// Check names match
		if obj1.GetName() != obj2.GetName() {
			t.Errorf("stack[%d]: names differ: %s vs %s", i, obj1.GetName(), obj2.GetName())
		}

		// Check namespaces match
		if obj1.GetNamespace() != obj2.GetNamespace() {
			t.Errorf("stack[%d]: namespaces differ: %s vs %s", i, obj1.GetNamespace(), obj2.GetNamespace())
		}
	}

	// Verify that modifying one stack doesn't affect the other (independence check)
	// Modify a deployment in stack1
	for _, obj := range stack1 {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
			dep.Spec.Replicas = int32Ptr(99)
			break
		}
	}

	// Check that stack2 wasn't affected
	for _, obj := range stack2 {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == "api" {
			if dep.Spec.Replicas != nil && *dep.Spec.Replicas == 99 {
				t.Error("modifying stack1 affected stack2 - stacks are not independent")
			}
			break
		}
	}
}

func TestGetSecureSecurityContext(t *testing.T) {
	uid := int64(65532)
	secCtx := getSecureSecurityContext(uid)

	if secCtx == nil {
		t.Fatal("getSecureSecurityContext returned nil")
	}

	// Check RunAsUser
	if secCtx.RunAsUser == nil || *secCtx.RunAsUser != uid {
		t.Errorf("expected RunAsUser == %d, got %v", uid, secCtx.RunAsUser)
	}

	// Check RunAsGroup
	if secCtx.RunAsGroup == nil || *secCtx.RunAsGroup != uid {
		t.Errorf("expected RunAsGroup == %d, got %v", uid, secCtx.RunAsGroup)
	}

	// Check RunAsNonRoot
	if secCtx.RunAsNonRoot == nil || !*secCtx.RunAsNonRoot {
		t.Error("expected RunAsNonRoot == true")
	}

	// Check AllowPrivilegeEscalation
	if secCtx.AllowPrivilegeEscalation == nil || *secCtx.AllowPrivilegeEscalation {
		t.Error("expected AllowPrivilegeEscalation == false")
	}

	// Check ReadOnlyRootFilesystem
	if secCtx.ReadOnlyRootFilesystem == nil || !*secCtx.ReadOnlyRootFilesystem {
		t.Error("expected ReadOnlyRootFilesystem == true")
	}

	// Check Capabilities.Drop contains "ALL"
	if secCtx.Capabilities == nil {
		t.Fatal("Capabilities is nil")
	}
	hasDropAll := false
	for _, cap := range secCtx.Capabilities.Drop {
		if cap == "ALL" {
			hasDropAll = true
			break
		}
	}
	if !hasDropAll {
		t.Error("expected Capabilities.Drop to contain \"ALL\"")
	}

	// Check SeccompProfile
	if secCtx.SeccompProfile == nil {
		t.Error("SeccompProfile is nil")
	} else if secCtx.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("expected SeccompProfile.Type == RuntimeDefault, got %s", secCtx.SeccompProfile.Type)
	}
}

// Helper function
func int32Ptr(i int32) *int32 {
	return &i
}
