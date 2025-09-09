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

// Constants for repeated strings (linter: goconst)
const (
	networkPolicyDisabled  = "disabled"
	networkIsolationNone   = "none"
	postgresServiceName    = "postgres-service"
	externalDatabaseAccess = "external-database-access"
	apiDeploymentName      = "api"
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
		if err := applyK03ToStack(&appStack, targetResource, namespace); err != nil {
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
		if err := applyK08ToStack(&appStack, targetResource, namespace); err != nil {
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
			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK03ToStack modifies the baseline stack to apply overly permissive RBAC configurations
func applyK03ToStack(appStack *[]client.Object, targetDeployment, namespace string) error {
	// Find and modify the target deployment within the stack
	for _, obj := range *appStack {
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
func createClusterAdminRBAC(appStack *[]client.Object, namespace string) error {
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
	for i, obj := range *appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert binding right after service account
			*appStack = append((*appStack)[:i+1], append([]client.Object{binding}, (*appStack)[i+1:]...)...)
			break
		}
	}

	return nil
}

// createSecretAccessRBAC grants broad secret access across the cluster
func createSecretAccessRBAC(appStack *[]client.Object, namespace string) error {
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
	for i, obj := range *appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			*appStack = append((*appStack)[:i+1], append([]client.Object{role, binding}, (*appStack)[i+1:]...)...)
			break
		}
	}

	return nil
}

// createCrossNamespaceRBAC grants access to sensitive namespaces
func createCrossNamespaceRBAC(appStack *[]client.Object, namespace string) error {
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
	for i, obj := range *appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			*appStack = append((*appStack)[:i+1], append([]client.Object{role, binding}, (*appStack)[i+1:]...)...)
			break
		}
	}

	return nil
}

// createNodeAccessRBAC grants access to node resources
func createNodeAccessRBAC(appStack *[]client.Object, namespace string) error {
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
	for i, obj := range *appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			*appStack = append((*appStack)[:i+1], append([]client.Object{role, binding}, (*appStack)[i+1:]...)...)
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
			// Randomly choose one of four K06 vulnerability types (removed problematic cases)
			localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
			vulnType := localRand.Intn(4)

			switch vulnType {
			case 0: // Auto-mount service account tokens
				dep.Spec.Template.Spec.AutomountServiceAccountToken = ptr.To(true)

			case 1: // Default service account usage (remove explicit serviceAccountName)
				dep.Spec.Template.Spec.ServiceAccountName = ""

			case 2: // Service account token annotation
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["kubernetes.io/service-account.token"] = "required"

			case 3: // Default service account annotation
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["auth.kubernetes.io/default-account"] = "temporary"
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK07ToStack modifies the baseline stack to demonstrate missing network segmentation controls
func applyK07ToStack(appStack []client.Object, targetDeployment, namespace string) error {
	// K07 vulnerabilities are about MISSING network controls rather than broken ones
	// We demonstrate this by either disabling network policies or exposing services externally

	// Randomly choose one of four K07 vulnerability demonstrations
	localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	vulnType := localRand.Intn(4)

	switch vulnType {
	case 0: // Unrestricted pod-to-pod communication (network policy disabled annotation)
		if err := addNetworkPolicyDisabledAnnotation(appStack, targetDeployment); err != nil {
			return err
		}

	case 1: // Network isolation disabled annotation
		if err := addNetworkIsolationDisabledAnnotation(appStack, targetDeployment); err != nil {
			return err
		}

	case 2: // Database exposure (modify postgres service to NodePort)
		if err := exposePostgresServiceAsNodePort(appStack); err != nil {
			return err
		}

	case 3: // Service exposure annotation
		if err := addServiceExposureAnnotation(appStack); err != nil {
			return err
		}
	}

	return nil
}

// addNetworkPolicyDisabledAnnotation adds annotation indicating network policies are disabled
func addNetworkPolicyDisabledAnnotation(appStack []client.Object, targetDeployment string) error {
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["networking.kubernetes.io/network-policy"] = networkPolicyDisabled
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// addNetworkIsolationDisabledAnnotation adds annotation indicating network isolation is disabled
func addNetworkIsolationDisabledAnnotation(appStack []client.Object, targetDeployment string) error {
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["networking.kubernetes.io/isolation"] = networkIsolationNone
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// addServiceExposureAnnotation adds annotation to postgres service without changing service type
func addServiceExposureAnnotation(appStack []client.Object) error {
	for _, obj := range appStack {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == postgresServiceName {
			if svc.Annotations == nil {
				svc.Annotations = make(map[string]string)
			}
			svc.Annotations["networking.kubernetes.io/exposure"] = externalDatabaseAccess
			return nil
		}
	}
	return fmt.Errorf("%s not found in baseline stack", postgresServiceName)
}

// exposePostgresServiceAsNodePort modifies the postgres service to be externally accessible
func exposePostgresServiceAsNodePort(appStack []client.Object) error {
	for _, obj := range appStack {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == postgresServiceName {
			// Change the service type from ClusterIP to NodePort to expose it externally
			svc.Spec.Type = corev1.ServiceTypeNodePort

			// Add a specific NodePort for the postgres port
			for i := range svc.Spec.Ports {
				if svc.Spec.Ports[i].Name == "postgres" || svc.Spec.Ports[i].Port == 5432 {
					svc.Spec.Ports[i].NodePort = 30432 // Expose postgres on node port 30432
				}
			}

			return nil
		}
	}

	return fmt.Errorf("%s not found in baseline stack", postgresServiceName)
}

// applyK08ToStack modifies the baseline stack to apply secrets management vulnerabilities
func applyK08ToStack(appStack *[]client.Object, targetDeployment, namespace string) error {
	// Randomly choose one of three K08 vulnerability types (removed problematic cases)
	localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	vulnType := localRand.Intn(3)

	switch vulnType {
	case 0: // Secret data in ConfigMaps
		if err := moveSecretsToConfigMap(appStack, targetDeployment, namespace); err != nil {
			return err
		}

	case 1: // Hardcoded secrets annotation (without changing environment)
		if err := addHardcodedSecretsAnnotation(appStack, targetDeployment); err != nil {
			return err
		}

	case 2: // Insecure volume permissions annotation (without changing volumes)
		if err := addInsecureVolumeAnnotation(appStack, targetDeployment); err != nil {
			return err
		}
	}

	return nil
}

// addHardcodedSecretsAnnotation adds annotation indicating hardcoded secrets (without changing environment)
func addHardcodedSecretsAnnotation(appStack *[]client.Object, targetDeployment string) error {
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["config.kubernetes.io/hardcoded-secrets"] = "development-mode"
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// addInsecureVolumeAnnotation adds annotation indicating insecure volume permissions (without changing volumes)
func addInsecureVolumeAnnotation(appStack *[]client.Object, targetDeployment string) error {
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
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
func moveSecretsToConfigMap(appStack *[]client.Object, targetDeployment, namespace string) error {
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
	for _, obj := range *appStack {
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
	for i, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Insert ConfigMap right after the deployment
			*appStack = append((*appStack)[:i+1], append([]client.Object{insecureConfigMap}, (*appStack)[i+1:]...)...)
			break
		}
	}

	return nil
}

// The old functions below are no longer used - they've been replaced by the ToStack variants above
