package breaker

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// Constants for commonly used strings
const (
	paymentAPIKeySecret = "payment-api-key"
	testAPIKey          = "sk_test_12345"
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
	case "K07":
		if err := applyK07ToStack(appStack, targetResource, namespace); err != nil {
			return fmt.Errorf("failed to apply K07 vulnerability: %w", err)
		}
	case "K08":
		if err := applyK08ToStack(appStack, targetResource, namespace); err != nil {
			return fmt.Errorf("failed to apply K08 vulnerability: %w", err)
		}
	// K09 (Misconfigured Cluster Components) and K10 (Outdated and Vulnerable Kubernetes Components)
	// are not implemented as they require cluster-level administrative access and would affect
	// the entire cluster rather than being contained within individual lab namespaces
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
			_ = append(appStack[:i+1], append([]client.Object{binding}, appStack[i+1:]...)...)
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
			_ = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
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
			_ = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
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
			_ = append(appStack[:i+1], append([]client.Object{role, binding}, appStack[i+1:]...)...)
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
func replaceSecretsWithPlaintext(container *corev1.Container, _ string) error {
	for i, env := range container.Env {
		if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
			// Replace secret references with hardcoded values based on the secret
			var plainValue string
			switch {
			case env.ValueFrom.SecretKeyRef.Name == "postgres-credentials" && env.ValueFrom.SecretKeyRef.Key == "username":
				plainValue = "appuser"
			case env.ValueFrom.SecretKeyRef.Name == "postgres-credentials" && env.ValueFrom.SecretKeyRef.Key == "password":
				plainValue = "apppassword"
			case env.ValueFrom.SecretKeyRef.Name == paymentAPIKeySecret && env.ValueFrom.SecretKeyRef.Key == "key":
				plainValue = testAPIKey
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

// applyK07ToStack modifies the baseline stack to demonstrate missing network segmentation controls
func applyK07ToStack(appStack []client.Object, targetDeployment, namespace string) error {
	// K07 vulnerabilities are about MISSING network controls rather than broken ones
	// The baseline already has no NetworkPolicies, but we'll add vulnerable network configurations
	// to make the lack of segmentation more obvious to security scanners

	// Randomly choose one of four K07 vulnerability demonstrations
	localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	vulnType := localRand.Intn(4)

	switch vulnType {
	case 0: // Unrestricted pod-to-pod communication (add annotation indicating this is intentional)
		if err := addUnrestrictedPodAnnotation(appStack, targetDeployment); err != nil {
			return err
		}

	case 1: // Database exposure (add service with broad access)
		if err := createExposedDatabaseService(appStack, namespace); err != nil {
			return err
		}

	case 2: // External traffic bypass (add NodePort service bypassing ingress)
		if err := createBypassService(appStack, targetDeployment, namespace); err != nil {
			return err
		}

	case 3: // Cross-namespace communication (add service with external name)
		if err := createCrossNamespaceService(appStack, targetDeployment, namespace); err != nil {
			return err
		}
	}

	return nil
}

// addUnrestrictedPodAnnotation adds annotations indicating unrestricted pod communication
func addUnrestrictedPodAnnotation(appStack []client.Object, targetDeployment string) error {
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			// Annotation that indicates network policies are disabled
			dep.Spec.Template.Annotations["networking.kubernetes.io/network-policy"] = "disabled"
			dep.Spec.Template.Annotations["networking.kubernetes.io/isolation"] = "none"
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// createExposedDatabaseService creates a service that exposes database to all pods
func createExposedDatabaseService(appStack []client.Object, namespace string) error {
	exposedService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "database-direct-access",
			Namespace: namespace,
			Annotations: map[string]string{
				"networking.kubernetes.io/access-policy": "unrestricted",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "postgres-db"},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port:       5432,
					TargetPort: intstr.FromInt(5432),
					Name:       "postgres-exposed",
				},
			},
		},
	}

	// Add the exposed service to the stack
	for i, obj := range appStack {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == "postgres-service" {
			// Insert exposed service right after the regular postgres service
			_ = append(appStack[:i+1], append([]client.Object{exposedService}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// createBypassService creates a NodePort service that bypasses ingress controls
func createBypassService(appStack []client.Object, targetDeployment, namespace string) error {
	// Create a NodePort service for the target deployment to bypass ingress
	bypassService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-bypass", targetDeployment),
			Namespace: namespace,
			Annotations: map[string]string{
				"networking.kubernetes.io/bypass-ingress": "true",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": targetDeployment},
			Type:     corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Port:       8080,
					TargetPort: intstr.FromInt(80),
					NodePort:   30080, // Fixed NodePort for direct external access
					Name:       "bypass-http",
				},
			},
		},
	}

	// Add the bypass service to the stack
	for i, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Insert bypass service right after the target deployment
			_ = append(appStack[:i+1], append([]client.Object{bypassService}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// createCrossNamespaceService creates a service that allows cross-namespace communication
func createCrossNamespaceService(appStack []client.Object, targetDeployment, namespace string) error {
	crossNsService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-cross-ns", targetDeployment),
			Namespace: namespace,
			Annotations: map[string]string{
				"networking.kubernetes.io/cross-namespace": "enabled",
			},
		},
		Spec: corev1.ServiceSpec{
			// ExternalName service pointing to a service in another namespace
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: "kube-dns.kube-system.svc.cluster.local",
			Ports: []corev1.ServicePort{
				{
					Port:       53,
					TargetPort: intstr.FromInt(53),
					Name:       "dns-cross-access",
				},
			},
		},
	}

	// Add the cross-namespace service to the stack
	for i, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Insert cross-ns service right after the target deployment
			_ = append(appStack[:i+1], append([]client.Object{crossNsService}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// applyK08ToStack modifies the baseline stack to apply secrets management vulnerabilities
func applyK08ToStack(appStack []client.Object, targetDeployment, namespace string) error {
	// Randomly choose one of four K08 vulnerability types
	localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	vulnType := localRand.Intn(4)

	switch vulnType {
	case 0: // Hardcoded secrets in environment variables
		if err := replaceSecretsWithHardcoded(appStack, targetDeployment); err != nil {
			return err
		}

	case 1: // Insecure volume permissions
		if err := makeSecretVolumeInsecure(appStack, targetDeployment); err != nil {
			return err
		}

	case 2: // Secret data in ConfigMaps
		if err := moveSecretsToConfigMap(appStack, targetDeployment, namespace); err != nil {
			return err
		}

	case 3: // Base64 encoded secrets (visible)
		if err := exposeSecretsAsBase64(appStack, targetDeployment); err != nil {
			return err
		}
	}

	return nil
}

// replaceSecretsWithHardcoded converts secret references to plain environment variables
func replaceSecretsWithHardcoded(appStack []client.Object, targetDeployment string) error {
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Replace secret references with hardcoded values
			for i, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					// Convert secret reference to hardcoded value
					var plainValue string
					switch {
					case env.ValueFrom.SecretKeyRef.Name == "jwt-secret" || env.Name == "JWT_SECRET":
						plainValue = "super-secure-jwt-signing-key-2024"
					case env.ValueFrom.SecretKeyRef.Name == "redis-password" || env.Name == "REDIS_PASSWORD":
						plainValue = "redis-secure-password-123"
					case env.ValueFrom.SecretKeyRef.Name == paymentAPIKeySecret || env.Name == "API_KEY":
						plainValue = testAPIKey
					default:
						continue
					}

					// Replace with hardcoded value
					container.Env[i] = corev1.EnvVar{
						Name:  env.Name,
						Value: plainValue,
					}
				}
			}

			// Add annotation indicating this was done for convenience (looks legitimate)
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["config.kubernetes.io/hardcoded-secrets"] = "development-mode"
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// makeSecretVolumeInsecure changes secret volume permissions to world-readable
func makeSecretVolumeInsecure(appStack []client.Object, targetDeployment string) error {
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Find and modify secret volumes
			for i, volume := range dep.Spec.Template.Spec.Volumes {
				if volume.Secret != nil {
					// Make secret volume world-readable
					dep.Spec.Template.Spec.Volumes[i].Secret.DefaultMode = ptr.To(int32(0777))
				}
			}

			// Add annotation that looks like troubleshooting
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["security.kubernetes.io/volume-permissions"] = "debugging-enabled"
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// moveSecretsToConfigMap creates a ConfigMap with secret data instead of using Secrets
func moveSecretsToConfigMap(appStack []client.Object, targetDeployment, namespace string) error {
	// Create a ConfigMap with sensitive data
	insecureConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-config", targetDeployment),
			Namespace: namespace,
			Annotations: map[string]string{
				"config.kubernetes.io/contains-secrets": "true",
			},
		},
		Data: map[string]string{
			"jwt-secret":     "super-secure-jwt-signing-key-2024",
			"redis-password": "redis-secure-password-123",
			"database-url":   "postgres://appuser:apppassword@postgres-service:5432/appdb",
			"api-key":        testAPIKey,
		},
	}

	// Find the target deployment and modify it to use ConfigMap
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Add ConfigMap environment variables
			configEnvs := []corev1.EnvVar{
				{
					Name: "JWT_SECRET_FROM_CONFIG",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: insecureConfigMap.Name,
							},
							Key: "jwt-secret",
						},
					},
				},
				{
					Name: "API_KEY_FROM_CONFIG",
					ValueFrom: &corev1.EnvVarSource{
						ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: insecureConfigMap.Name,
							},
							Key: "api-key",
						},
					},
				},
			}

			// Add the config-based environment variables
			container.Env = append(container.Env, configEnvs...)
			break
		}
	}

	// Add the ConfigMap to the stack
	for i, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Insert ConfigMap right after the deployment
			_ = append(appStack[:i+1], append([]client.Object{insecureConfigMap}, appStack[i+1:]...)...)
			break
		}
	}

	return nil
}

// exposeSecretsAsBase64 changes StringData to Data to expose base64 encoding
func exposeSecretsAsBase64(appStack []client.Object, _ string) error {

	for _, obj := range appStack {
		if secret, ok := obj.(*corev1.Secret); ok {
			// Look for secrets related to the target deployment
			if secret.Name == "api-secrets" || secret.Name == "redis-auth" || secret.Name == paymentAPIKeySecret {
				// Convert StringData to Data (exposes base64 encoding)
				if secret.StringData != nil {
					if secret.Data == nil {
						secret.Data = make(map[string][]byte)
					}

					// Convert all StringData to base64 Data
					for key, value := range secret.StringData {
						secret.Data[key] = []byte(base64.StdEncoding.EncodeToString([]byte(value)))
					}

					// Clear StringData to force use of Data field
					secret.StringData = nil
				}

				// Add annotation indicating this exposes secrets
				if secret.Annotations == nil {
					secret.Annotations = make(map[string]string)
				}
				secret.Annotations["encoding.kubernetes.io/format"] = "base64-visible"
				break
			}
		}
	}
	return nil
}

// The old functions below are no longer used - they've been replaced by the ToStack variants above
