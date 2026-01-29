package breaker

import (
	"context"
	"fmt"
	"math/rand"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, targetResource, namespace string, subIssue *int, rng *rand.Rand) error {
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
		if err := applyK01ToStack(appStack, targetResource, subIssue, rng); err != nil {
			return fmt.Errorf("failed to apply K01 vulnerability: %w", err)
		}
	case "K02":
		if err := applyK02ToStack(appStack, targetResource, subIssue); err != nil {
			return fmt.Errorf("failed to apply K02 vulnerability: %w", err)
		}
	case "K03":
		if err := applyK03ToStack(&appStack, targetResource, namespace, subIssue, rng); err != nil {
			return fmt.Errorf("failed to apply K03 vulnerability: %w", err)
		}
	// K04 (Lack of Centralized Policy Enforcement) and K05 (Inadequate Logging and Monitoring)
	// are not implemented as they require external infrastructure (OPA Gatekeeper, SIEM systems)
	// rather than resource-level misconfigurations that can be demonstrated in this lab environment
	case "K06":
		if err := applyK06ToStack(appStack, targetResource, subIssue, rng); err != nil {
			return fmt.Errorf("failed to apply K06 vulnerability: %w", err)
		}
	case "K07":
		if err := applyK07ToStack(&appStack, targetResource, namespace, subIssue, rng); err != nil {
			return fmt.Errorf("failed to apply K07 vulnerability: %w", err)
		}
	case "K08":
		if err := applyK08ToStack(&appStack, targetResource, namespace, subIssue, rng); err != nil {
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
				// Resource exists — update it with the vulnerable spec
				// Fetch the existing resource to get its resourceVersion
				existing := obj.DeepCopyObject().(client.Object)
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
					return fmt.Errorf("failed to get existing resource %s: %w", obj.GetName(), err)
				}
				// Copy resourceVersion to our modified object
				obj.SetResourceVersion(existing.GetResourceVersion())
				if err := c.Update(ctx, obj); err != nil {
					return fmt.Errorf("failed to update existing resource %s: %w", obj.GetName(), err)
				}
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
func applyK01ToStack(appStack []client.Object, targetDeployment string, subIssue *int, rng *rand.Rand) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Choose vulnerability type based on subIssue parameter or randomly
			var vulnType int
			if subIssue != nil {
				if *subIssue < 0 || *subIssue > 2 {
					return fmt.Errorf("subIssue %d out of range for K01 (valid: 0-2)", *subIssue)
				}
				vulnType = *subIssue
			} else {
				// Randomly choose one of three K01 vulnerability types
				vulnType = rng.Intn(3)
			}

			switch vulnType {
			case 0: // Privileged container
				// Preserve existing security context but add privileged vulnerability
				if container.SecurityContext == nil {
					container.SecurityContext = &corev1.SecurityContext{}
				}
				container.SecurityContext.Privileged = ptr.To(true)
				// When privileged=true, allowPrivilegeEscalation must be nil or true (cannot be false)
				container.SecurityContext.AllowPrivilegeEscalation = nil
				// Add annotation indicating why this is privileged (looks realistic)
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.privileged"] = "host-access-required"

			case 1: // Running as root
				// Preserve existing security context but modify user to run as root
				if container.SecurityContext == nil {
					container.SecurityContext = &corev1.SecurityContext{}
				}
				container.SecurityContext.RunAsUser = ptr.To(int64(0))
				container.SecurityContext.RunAsNonRoot = ptr.To(false) // Override the baseline runAsNonRoot
				// Add annotation that looks like a legitimate override
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.runAsRoot"] = "legacy-compatibility"

			case 2: // Dangerous capabilities
				// Preserve existing security context but add dangerous capabilities
				if container.SecurityContext == nil {
					container.SecurityContext = &corev1.SecurityContext{}
				}
				if container.SecurityContext.Capabilities == nil {
					container.SecurityContext.Capabilities = &corev1.Capabilities{}
				}
				container.SecurityContext.Capabilities.Add = []corev1.Capability{
					"SYS_ADMIN",
					"NET_ADMIN",
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
func applyK02ToStack(appStack []client.Object, targetDeployment string, subIssue *int) error {
	// Define vulnerable images with critical CVEs for realistic security testing
	vulnerableImages := []struct {
		deployment string
		image      string
	}{
		{"api", "node:10-alpine"},              // 0: 4 critical CVEs vs current node:22-alpine
		{"webapp", "nginx:1.15-alpine"},        // 1: 4 critical CVEs vs current nginx:1.29.1-alpine
		{"user-service", "python:3.5-alpine"},  // 2: 11 critical CVEs vs current python:3.13-alpine
		{"payment-service", "ruby:2.6-alpine"}, // 3: 4 critical CVEs vs current ruby:3.3-alpine
		{"grafana", "grafana/grafana:9.0.0"},   // 4: vs current grafana/grafana:12.0.0
	}

	var selectedTarget string
	var vulnerableImage string

	if subIssue != nil {
		// Use specified sub-issue index
		if *subIssue < 0 || *subIssue >= len(vulnerableImages) {
			return fmt.Errorf("subIssue %d out of range for K02 (valid: 0-%d)", *subIssue, len(vulnerableImages)-1)
		}
		selectedTarget = vulnerableImages[*subIssue].deployment
		vulnerableImage = vulnerableImages[*subIssue].image
	} else {
		// Use target deployment (existing behavior)
		vulnerableImageMap := map[string]string{
			"api":             "node:10-alpine",
			"webapp":          "nginx:1.15-alpine",
			"user-service":    "python:3.5-alpine",
			"payment-service": "ruby:2.6-alpine",
			"grafana":         "grafana/grafana:9.0.0",
		}
		var exists bool
		vulnerableImage, exists = vulnerableImageMap[targetDeployment]
		if !exists {
			return fmt.Errorf("no vulnerable image defined for target: %s", targetDeployment)
		}
		selectedTarget = targetDeployment
	}

	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == selectedTarget {
			// Replace the image with the vulnerable version
			dep.Spec.Template.Spec.Containers[0].Image = vulnerableImage
			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", selectedTarget)
}

// applyK03ToStack modifies the baseline stack to apply overly permissive RBAC configurations
func applyK03ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) error {
	// Find and modify the target deployment within the stack
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Choose vulnerability type based on subIssue parameter or randomly
			var vulnType int
			if subIssue != nil {
				if *subIssue < 0 || *subIssue > 2 {
					return fmt.Errorf("subIssue %d out of range for K03 (valid: 0-2)", *subIssue)
				}
				vulnType = *subIssue
			} else {
				// Randomly choose one of three K03 vulnerability types (all namespace-scoped)
				vulnType = rng.Intn(3)
			}

			switch vulnType {
			case 0: // Namespace Overpermissive Access (namespace-scoped)
				if err := createNamespaceOverpermissiveRBAC(appStack, namespace); err != nil {
					return err
				}
			case 1: // Default Service Account Permissions (namespace-scoped)
				if err := createDefaultServiceAccountRBAC(appStack, namespace); err != nil {
					return err
				}
			case 2: // Excessive Secrets Access (namespace-scoped)
				if err := createExcessiveSecretsRBAC(appStack, namespace); err != nil {
					return err
				}
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// createNamespaceOverpermissiveRBAC grants overly broad permissions within the namespace only
func createNamespaceOverpermissiveRBAC(appStack *[]client.Object, namespace string) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-overpermissive", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "development-testing",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"list", "watch", "get"}, // Too broad - can see all secrets
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"list", "watch", "get", "create", "update"}, // Excessive permissions
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"list", "watch", "get", "patch"}, // Can modify deployments
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-overpermissive-binding", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
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

// createDefaultServiceAccountRBAC grants excessive permissions to the service account
func createDefaultServiceAccountRBAC(appStack *[]client.Object, namespace string) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-default-permissions", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
				"rbac.k8s.lab/binding":    fmt.Sprintf("%s-default-binding", namespace),
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "legacy-compatibility",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services"},
				Verbs:     []string{"get", "list", "watch", "create"}, // Should not have create permissions
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch"}, // Can read all configmaps
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-default-binding", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
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
			Kind:     "Role",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	// Add the RBAC resources to the stack (Role first, then RoleBinding)
	for i, obj := range *appStack {
		if _, ok := obj.(*corev1.ServiceAccount); ok {
			// Insert role and binding right after service account
			*appStack = append((*appStack)[:i+1], append([]client.Object{role, binding}, (*appStack)[i+1:]...)...)
			break
		}
	}

	return nil
}

// createExcessiveSecretsRBAC grants overly broad access to secrets within the namespace
func createExcessiveSecretsRBAC(appStack *[]client.Object, namespace string) error {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secrets-reader", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "debug-troubleshooting",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch"}, // Can read ALL secrets in namespace
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch", "delete"}, // Unnecessary delete permission
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secrets-binding", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
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

// applyK06ToStack modifies the baseline stack to apply broken authentication vulnerabilities
func applyK06ToStack(appStack []client.Object, targetDeployment string, subIssue *int, rng *rand.Rand) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Choose vulnerability type based on subIssue parameter or randomly
			var vulnType int
			if subIssue != nil {
				if *subIssue < 0 || *subIssue > 4 {
					return fmt.Errorf("subIssue %d out of range for K06 (valid: 0-4)", *subIssue)
				}
				vulnType = *subIssue
			} else {
				// Randomly choose one of five K06 vulnerability types (removed duplicate K06:2)
				vulnType = rng.Intn(5)
			}

			switch vulnType {
			case 0: // Default service account usage (remove explicit serviceAccountName)
				dep.Spec.Template.Spec.ServiceAccountName = ""

			case 1: // Auto-mount service account token (scanner-detectable via Kubescape C-0034)
				dep.Spec.Template.Spec.AutomountServiceAccountToken = ptr.To(true)

			case 2: // Missing fsGroup in PodSecurityContext (flagged by Kubescape C-0057)
				// Add a PodSecurityContext with FSGroup, then remove it to create the vulnerability
				if dep.Spec.Template.Spec.SecurityContext == nil {
					dep.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{}
				}
				dep.Spec.Template.Spec.SecurityContext.FSGroup = nil // Remove fsGroup to create vulnerability

			case 3: // Root user with volume access (flagged by Kubescape C-0013)
				for i := range dep.Spec.Template.Spec.Containers {
					if dep.Spec.Template.Spec.Containers[i].SecurityContext != nil {
						dep.Spec.Template.Spec.Containers[i].SecurityContext.RunAsUser = ptr.To(int64(0))
						// Note: keeping runAsNonRoot unchanged - only modifying runAsUser creates the vulnerability
					}
				}

			case 4: // Privileged container with volume access (flagged by Kubescape C-0016)
				for i := range dep.Spec.Template.Spec.Containers {
					if dep.Spec.Template.Spec.Containers[i].SecurityContext != nil {
						dep.Spec.Template.Spec.Containers[i].SecurityContext.Privileged = ptr.To(true)
					}
				}
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK07ToStack modifies the baseline stack to demonstrate missing network segmentation controls
func applyK07ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) error {
	// K07 vulnerabilities are about MISSING network controls rather than broken ones
	// We demonstrate this by either disabling network policies or exposing services externally
	// Note: targetDeployment parameter kept for API consistency with other vulnerability functions
	_ = targetDeployment

	// Choose vulnerability type based on subIssue parameter or randomly
	var vulnType int
	if subIssue != nil {
		if *subIssue < 0 || *subIssue > 3 {
			return fmt.Errorf("subIssue %d out of range for K07 (valid: 0-3)", *subIssue)
		}
		vulnType = *subIssue
	} else {
		// Randomly choose one of four K07 vulnerability demonstrations
		vulnType = rng.Intn(4)
	}

	switch vulnType {
	case 0: // Unrestricted pod-to-pod communication (delete network policy)
		if err := addNetworkPolicyDisabledAnnotation(appStack); err != nil {
			return err
		}

	case 1: // Network isolation disabled (create allow-all network policy)
		if err := addNetworkIsolationDisabledAnnotation(appStack, namespace); err != nil {
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

// addNetworkPolicyDisabledAnnotation deletes NetworkPolicy to demonstrate missing network controls
func addNetworkPolicyDisabledAnnotation(appStack *[]client.Object) error {
	// Remove any NetworkPolicy from the stack to demonstrate missing network controls
	var updatedStack []client.Object
	for _, obj := range *appStack {
		if _, ok := obj.(*networkingv1.NetworkPolicy); !ok {
			updatedStack = append(updatedStack, obj)
		}
	}
	*appStack = updatedStack
	return nil
}

// addNetworkIsolationDisabledAnnotation creates an allow-all NetworkPolicy
func addNetworkIsolationDisabledAnnotation(appStack *[]client.Object, namespace string) error {
	// Create an allow-all NetworkPolicy
	allowAllPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-all-traffic",
			Namespace: namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{}, // Empty selector matches all pods
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{}, // Empty rule allows all ingress
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{}, // Empty rule allows all egress
			},
		},
	}

	// Add the allow-all policy to the stack
	*appStack = append(*appStack, allowAllPolicy)
	return nil
}

// addServiceExposureAnnotation changes the postgres service type to LoadBalancer
func addServiceExposureAnnotation(appStack *[]client.Object) error {
	for _, obj := range *appStack {
		if svc, ok := obj.(*corev1.Service); ok && svc.Name == postgresServiceName {
			// Change the service type from ClusterIP to LoadBalancer to expose it externally
			svc.Spec.Type = corev1.ServiceTypeLoadBalancer
			return nil
		}
	}
	return fmt.Errorf("%s not found in baseline stack", postgresServiceName)
}

// exposePostgresServiceAsNodePort modifies the postgres service to be externally accessible
func exposePostgresServiceAsNodePort(appStack *[]client.Object) error {
	for _, obj := range *appStack {
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
func applyK08ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) error {
	// Choose vulnerability type based on subIssue parameter or randomly
	var vulnType int
	if subIssue != nil {
		if *subIssue < 0 || *subIssue > 2 {
			return fmt.Errorf("subIssue %d out of range for K08 (valid: 0-2)", *subIssue)
		}
		vulnType = *subIssue
	} else {
		// Randomly choose one of three K08 vulnerability types
		vulnType = rng.Intn(3)
	}

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

// addHardcodedSecretsAnnotation adds hardcoded secrets as literal environment variables
func addHardcodedSecretsAnnotation(appStack *[]client.Object, targetDeployment string) error {
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Add hardcoded secrets as literal environment variables
			hardcodedEnvs := []corev1.EnvVar{
				{
					Name:  "JWT_SECRET",
					Value: "super-secure-jwt-signing-key-2024",
				},
				{
					Name:  "API_KEY",
					Value: testAPIKey,
				},
				{
					Name:  "REDIS_PASSWORD",
					Value: "redis-secure-password-123",
				},
			}

			container.Env = append(container.Env, hardcodedEnvs...)
			return nil
		}
	}
	return fmt.Errorf("target deployment %s not found", targetDeployment)
}

// addInsecureVolumeAnnotation mounts a secret volume with insecure permissions (0644)
func addInsecureVolumeAnnotation(appStack *[]client.Object, targetDeployment string) error {
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Add a secret volume with insecure permissions
			insecureMode := int32(0644) // World-readable

			// Check if there's already a secret volume, modify its permissions
			volumeModified := false
			for i := range dep.Spec.Template.Spec.Volumes {
				if dep.Spec.Template.Spec.Volumes[i].Secret != nil {
					dep.Spec.Template.Spec.Volumes[i].Secret.DefaultMode = &insecureMode
					volumeModified = true
					break
				}
			}

			// If no secret volume exists, create one
			if !volumeModified {
				secretVolume := corev1.Volume{
					Name: "insecure-secrets",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName:  paymentAPIKeySecret,
							DefaultMode: &insecureMode,
						},
					},
				}
				dep.Spec.Template.Spec.Volumes = append(dep.Spec.Template.Spec.Volumes, secretVolume)

				// Also add a volume mount to make it more realistic
				volumeMount := corev1.VolumeMount{
					Name:      "insecure-secrets",
					MountPath: "/etc/secrets",
					ReadOnly:  true,
				}
				dep.Spec.Template.Spec.Containers[0].VolumeMounts = append(
					dep.Spec.Template.Spec.Containers[0].VolumeMounts,
					volumeMount,
				)
			}

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
