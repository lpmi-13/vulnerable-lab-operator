package breaker

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// BreakCluster applies the specified vulnerability to the cluster using build-with-vulnerabilities approach
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, targetResource, namespace string) error {
	logger := log.FromContext(ctx)

	logger.Info("Applying vulnerability", "vulnerability", vulnerabilityID, "namespace", namespace)

	// First, ensure the namespace exists
	if err := createNamespaceIfNotExists(ctx, c, namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Get the baseline application stack
	appStack := baseline.GetAppStack(namespace)

	// Apply the vulnerability to the target resource within the stack before deployment
	switch vulnerabilityID {
	case "K01":
		if err := applyK01ToStack(appStack, targetResource); err != nil {
			return fmt.Errorf("failed to apply K01 vulnerability: %w", err)
		}
	case "K02":
		if err := applyK02ToStack(appStack, targetResource); err != nil {
			return fmt.Errorf("failed to apply K02 vulnerability: %w", err)
		}
	case "K03":
		if err := applyK03ToStack(appStack, targetResource, namespace); err != nil {
			return fmt.Errorf("failed to apply K03 vulnerability: %w", err)
		}
	// K04 (Lack of Centralized Policy Enforcement) and K05 (Inadequate Logging and Monitoring)
	// are not implemented as they require external infrastructure (OPA Gatekeeper, SIEM systems)
	// rather than resource-level misconfigurations that can be demonstrated in this lab environment
	case "K06":
		if err := applyK06ToStack(appStack, targetResource); err != nil {
			return fmt.Errorf("failed to apply K06 vulnerability: %w", err)
		}
	// ... Add cases for K07, K08, K09, K10
	default:
		return fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}

	// Deploy the entire modified stack at once
	for _, obj := range appStack {
		if err := c.Create(ctx, obj); err != nil {
			if errors.IsAlreadyExists(err) {
				// Skip already existing resources for idempotency
				continue
			}
			return fmt.Errorf("failed to create resource %s: %w", obj.GetName(), err)
		}
	}

	logger.Info("Vulnerable stack deployment complete", "vulnerability", vulnerabilityID, "target", targetResource)
	return nil
}

// These helper functions are no longer needed since we use the baseline stack directly

// createNamespaceIfNotExists ensures the lab namespace exists
func createNamespaceIfNotExists(ctx context.Context, c client.Client, namespace string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}

	// Try to create, ignore if already exists
	err := c.Create(ctx, ns)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// InitializeLab function is no longer used - replaced by BreakCluster with build-with-vulnerabilities approach

// applyK01ToStack modifies the baseline stack to apply insecure workload configurations
func applyK01ToStack(appStack []client.Object, targetDeployment string) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Randomly choose one of three K01 vulnerability types
			localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
			vulnType := localRand.Intn(3)

			switch vulnType {
			case 0: // Privileged container
				container.SecurityContext = &corev1.SecurityContext{
					Privileged: ptr.To(true),
				}
				// Add annotation indicating why this is privileged (looks realistic)
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.privileged"] = "host-access-required"

			case 1: // Running as root
				container.SecurityContext = &corev1.SecurityContext{
					RunAsUser: ptr.To(int64(0)),
				}
				// Add annotation that looks like a legitimate override
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.runAsRoot"] = "legacy-compatibility"

			case 2: // Dangerous capabilities
				container.SecurityContext = &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"SYS_ADMIN",
							"NET_ADMIN",
						},
					},
				}
				// Add annotation that looks like a network requirement
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.capabilities"] = "network-management"
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK02ToStack modifies the baseline stack to apply supply chain vulnerabilities
func applyK02ToStack(appStack []client.Object, targetDeployment string) error {
	// Define vulnerable images that are realistic but outdated
	vulnerableImages := map[string]string{
		"api":             "node:16-alpine",        // vs current node:22-alpine
		"webapp":          "nginx:1.20-alpine",     // vs current nginx:1.25-alpine
		"user-service":    "python:3.9-alpine",     // vs current python:3.13-alpine
		"payment-service": "ruby:3.0-alpine",       // vs current ruby:3.3-alpine
		"grafana":         "grafana/grafana:9.0.0", // vs current grafana/grafana:12.0.0
	}

	vulnerableImage, exists := vulnerableImages[targetDeployment]
	if !exists {
		return fmt.Errorf("no vulnerable image defined for target: %s", targetDeployment)
	}

	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Replace the image with the vulnerable version
			dep.Spec.Template.Spec.Containers[0].Image = vulnerableImage

			// Add subtle annotations that scanners might detect but don't scream "vulnerable"
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["image.policy.ignore"] = "true"

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK03ToStack modifies the baseline stack to apply overly permissive RBAC configurations
func applyK03ToStack(appStack []client.Object, targetDeployment, namespace string) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Randomly choose one of four K03 vulnerability types
			localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
			vulnType := localRand.Intn(4)

			switch vulnType {
			case 0: // Cluster Admin Access
				if err := createClusterAdminRBAC(appStack, namespace); err != nil {
					return err
				}

			case 1: // Secret Access
				if err := createSecretAccessRBAC(appStack, namespace); err != nil {
					return err
				}

			case 2: // Cross-Namespace Access
				if err := createCrossNamespaceRBAC(appStack, namespace); err != nil {
					return err
				}

			case 3: // Node Access
				if err := createNodeAccessRBAC(appStack, namespace); err != nil {
					return err
				}
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// createClusterAdminRBAC grants cluster-admin permissions to the service account
func createClusterAdminRBAC(appStack []client.Object, namespace string) error {
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-cluster-access", namespace),
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "service-mesh-integration",
			},
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "restricted-sa",
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	// Add the RBAC resource to the stack
	for i, obj := range appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert binding right after service account
			appStack = append(appStack[:i+1], append([]client.Object{binding}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// createSecretAccessRBAC grants broad secret access across the cluster
func createSecretAccessRBAC(appStack []client.Object, namespace string) error {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-secret-reader", namespace),
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "config-management",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-secret-access", namespace),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "restricted-sa",
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	// Add the RBAC resources to the stack
	for i, obj := range appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			appStack = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// createCrossNamespaceRBAC grants access to sensitive namespaces
func createCrossNamespaceRBAC(appStack []client.Object, namespace string) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-system-access", namespace),
			Namespace: "kube-system",
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "monitoring-integration",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "configmaps"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-system-binding", namespace),
			Namespace: "kube-system",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "restricted-sa",
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	// Add the RBAC resources to the stack
	for i, obj := range appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			appStack = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// createNodeAccessRBAC grants access to node resources
func createNodeAccessRBAC(appStack []client.Object, namespace string) error {
	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-node-reader", namespace),
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "resource-monitoring",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes", "nodes/status", "nodes/metrics"},
				Verbs:     []string{"get", "list", "watch", "patch"},
			},
		},
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-node-access", namespace),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "restricted-sa",
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	// Add the RBAC resources to the stack
	for i, obj := range appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			appStack = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// applyK06ToStack modifies the baseline stack to apply broken authentication vulnerabilities
func applyK06ToStack(appStack []client.Object, targetDeployment string) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Randomly choose one of four K06 vulnerability types
			localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
			vulnType := localRand.Intn(4)

			switch vulnType {
			case 0: // Auto-mount service account tokens
				dep.Spec.Template.Spec.AutomountServiceAccountToken = ptr.To(true)
				// Add annotation that looks legitimate
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["kubernetes.io/service-account.token"] = "required"

			case 1: // Hardcoded credentials in environment (replace SecretKeyRef with plain values)
				container := &dep.Spec.Template.Spec.Containers[0]
				if err := replaceSecretsWithPlaintext(container, targetDeployment); err != nil {
					return err
				}

			case 2: // Default service account usage (remove explicit serviceAccountName)
				dep.Spec.Template.Spec.ServiceAccountName = ""
				// Add annotation that looks like a temporary override
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["auth.kubernetes.io/default-account"] = "temporary"

			case 3: // Exposed authentication headers in environment
				container := &dep.Spec.Template.Spec.Containers[0]
				addExposedAuthEnvironment(container, targetDeployment)
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// replaceSecretsWithPlaintext converts SecretKeyRef to plain environment variables
func replaceSecretsWithPlaintext(container *corev1.Container, deploymentName string) error {
	for i, env := range container.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			// Replace secret references with hardcoded values based on the secret
			var plainValue string
			switch {
			case env.ValueFrom.SecretKeyRef.Name == "postgres-credentials" && env.ValueFrom.SecretKeyRef.Key == "username":
				plainValue = "appuser"
			case env.ValueFrom.SecretKeyRef.Name == "postgres-credentials" && env.ValueFrom.SecretKeyRef.Key == "password":
				plainValue = "apppassword"
			case env.ValueFrom.SecretKeyRef.Name == "payment-api-key" && env.ValueFrom.SecretKeyRef.Key == "key":
				plainValue = "sk_test_12345"
			default:
				continue // Skip unknown secrets
			}

			// Replace with plain value
			container.Env[i] = corev1.EnvVar{
				Name:  env.Name,
				Value: plainValue,
			}
		}
	}
	return nil
}

// addExposedAuthEnvironment adds authentication tokens as plain environment variables
func addExposedAuthEnvironment(container *corev1.Container, deploymentName string) {
	// Add different auth tokens based on deployment type
	var authEnvs []corev1.EnvVar

	switch deploymentName {
	case "api":
		authEnvs = []corev1.EnvVar{
			{Name: "JWT_SECRET", Value: "super-secret-jwt-key-123"},
			{Name: "API_TOKEN", Value: "bearer-token-abcdef123456"},
		}
	case "user-service":
		authEnvs = []corev1.EnvVar{
			{Name: "AUTH_KEY", Value: "user-service-auth-key-789"},
			{Name: "SESSION_SECRET", Value: "session-secret-xyz789"},
		}
	case "payment-service":
		authEnvs = []corev1.EnvVar{
			{Name: "STRIPE_SECRET", Value: "sk_live_dangerous_key_456"},
			{Name: "WEBHOOK_SECRET", Value: "whsec_payment_webhook_secret"},
		}
	default:
		authEnvs = []corev1.EnvVar{
			{Name: "AUTH_TOKEN", Value: "generic-auth-token-123"},
			{Name: "SECRET_KEY", Value: "hardcoded-secret-key-456"},
		}
	}

	// Append authentication environment variables
	container.Env = append(container.Env, authEnvs...)
}

// The old functions below are no longer used - they've been replaced by the ToStack variants above
