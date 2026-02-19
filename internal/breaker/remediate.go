package breaker

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CheckRemediation checks if a specific vulnerability has been fixed.
// subIssue, when non-nil, restricts the check to only the specific applied sub-issue.
func CheckRemediation(ctx context.Context, c client.Client, vulnerabilityID, targetResource, namespace string, subIssue *int) (bool, error) {
	switch vulnerabilityID {
	case "K01":
		return checkK01(ctx, c, targetResource, namespace, subIssue)
	case "K03":
		return checkK03(ctx, c, targetResource, namespace, subIssue)
	// K04 (Lack of Centralized Policy Enforcement) and K05 (Inadequate Logging and Monitoring)
	// are not implemented as they require external infrastructure (OPA Gatekeeper, SIEM systems)
	// rather than resource-level misconfigurations that can be demonstrated in this lab environment
	case "K07":
		return checkK07(ctx, c, targetResource, namespace, subIssue)
	case "K08":
		return checkK08(ctx, c, targetResource, namespace, subIssue)
	// K09 (Misconfigured Cluster Components) and K10 (Outdated and Vulnerable Kubernetes Components)
	// are not implemented as they require cluster-level administrative access and would affect
	// the entire cluster rather than being contained within individual lab namespaces
	default:
		return false, fmt.Errorf("unknown vulnerability ID for remediation check: %s", vulnerabilityID)
	}
}

// checkK01 verifies if the specific deployment is no longer privileged
func checkK01(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment - now checking the actual target deployment name from baseline stack
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("K01 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	if subIssue != nil {
		return checkK01BySubIssue(ctx, dep, targetDeployment, *subIssue)
	}
	return checkK01All(ctx, dep, targetDeployment)
}

// checkK01BySubIssue checks only the specific K01 sub-issue that was applied
// Sub-issues: 0=Privileged(C-0057), 1=Non-root(C-0013), 2=HostPID/IPC(C-0038), 3=HostNetwork(C-0041), 4=HostPath(C-0048)
func checkK01BySubIssue(ctx context.Context, dep *appsv1.Deployment, targetDeployment string, subIssue int) (bool, error) {
	logger := log.FromContext(ctx)
	container := dep.Spec.Template.Spec.Containers[0]

	switch subIssue {
	case 0: // Privileged container
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			logger.Info("K01 vulnerability still active: privileged container", "target", targetDeployment)
			return false, nil
		}
	case 1: // Running as root
		if container.SecurityContext != nil && container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			logger.Info("K01 vulnerability still active: running as root", "target", targetDeployment)
			return false, nil
		}
	case 2: // Host PID/IPC access
		if dep.Spec.Template.Spec.HostPID || dep.Spec.Template.Spec.HostIPC {
			logger.Info("K01 vulnerability still active: hostPID/hostIPC enabled", "target", targetDeployment)
			return false, nil
		}
	case 3: // HostNetwork access
		if dep.Spec.Template.Spec.HostNetwork {
			logger.Info("K01 vulnerability still active: hostNetwork enabled", "target", targetDeployment)
			return false, nil
		}
	case 4: // HostPath volume mount
		for _, vol := range dep.Spec.Template.Spec.Volumes {
			if vol.HostPath != nil {
				logger.Info("K01 vulnerability still active: hostPath volume present", "target", targetDeployment)
				return false, nil
			}
		}
	}
	logger.Info("K01 vulnerability remediated", "target", targetDeployment, "subIssue", subIssue)
	return true, nil
}

// checkK01All checks all K01 sub-issues (fallback when no specific sub-issue is known)
func checkK01All(ctx context.Context, dep *appsv1.Deployment, targetDeployment string) (bool, error) {
	logger := log.FromContext(ctx)
	container := dep.Spec.Template.Spec.Containers[0]

	if container.SecurityContext != nil {
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			logger.Info("K01 vulnerability still active: privileged container", "target", targetDeployment)
			return false, nil
		}
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			logger.Info("K01 vulnerability still active: running as root", "target", targetDeployment)
			return false, nil
		}
	}
	if dep.Spec.Template.Spec.HostPID || dep.Spec.Template.Spec.HostIPC {
		logger.Info("K01 vulnerability still active: hostPID/hostIPC enabled", "target", targetDeployment)
		return false, nil
	}
	if dep.Spec.Template.Spec.HostNetwork {
		logger.Info("K01 vulnerability still active: hostNetwork enabled", "target", targetDeployment)
		return false, nil
	}
	for _, vol := range dep.Spec.Template.Spec.Volumes {
		if vol.HostPath != nil {
			logger.Info("K01 vulnerability still active: hostPath volume present", "target", targetDeployment)
			return false, nil
		}
	}
	logger.Info("K01 vulnerability remediated: security context is now secure", "target", targetDeployment)
	return true, nil
}

// checkK03 verifies if the RBAC vulnerability has been fixed
// Sub-issues: 0=C-0015(secrets-access), 1=C-0188(pod-create), 2=C-0007(delete),
//
//	3=C-0063(portforward), 4=C-0002(exec)
//
//nolint:gocyclo // Each switch case checks one isolated RBAC resource; complexity is intentional
func checkK03(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// If a specific sub-issue was applied, check only that one
	if subIssue != nil {
		switch *subIssue {
		case 0: // Secrets access role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-secrets-access-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: secrets access role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check secrets access role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-secrets-access-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: secrets access binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check secrets access binding: %w", err)
			}
		case 1: // Pod creation role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-pod-create-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: pod-create role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check pod-create role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-pod-create-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: pod-create binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check pod-create binding: %w", err)
			}
		case 2: // Delete capabilities role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-delete-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: delete role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check delete role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-delete-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: delete binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check delete binding: %w", err)
			}
		case 3: // Portforward role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-portforward-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: portforward role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check portforward role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-portforward-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: portforward binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check portforward binding: %w", err)
			}
		case 4: // Exec role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-exec-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: exec role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check exec role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-exec-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: exec binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check exec binding: %w", err)
			}
		}
		logger.Info("K03 vulnerability remediated", "target", targetDeployment, "subIssue", *subIssue)
		return true, nil
	}

	// Fallback: check all sub-issues using label selector (backward compat when subIssue is nil)
	roleList := &rbacv1.RoleList{}
	if err := c.List(ctx, roleList, client.InNamespace(namespace),
		client.MatchingLabels{"rbac.k8s.lab/managed-by": "vulnerable-lab"}); err != nil {
		return false, fmt.Errorf("failed to list lab-managed Roles: %w", err)
	}
	if len(roleList.Items) > 0 {
		logger.Info("K03 vulnerability still active: lab-managed roles still present", "target", targetDeployment, "count", len(roleList.Items))
		return false, nil
	}

	rbList := &rbacv1.RoleBindingList{}
	if err := c.List(ctx, rbList, client.InNamespace(namespace),
		client.MatchingLabels{"rbac.k8s.lab/managed-by": "vulnerable-lab"}); err != nil {
		return false, fmt.Errorf("failed to list lab-managed RoleBindings: %w", err)
	}
	if len(rbList.Items) > 0 {
		logger.Info("K03 vulnerability still active: lab-managed rolebindings still present", "target", targetDeployment, "count", len(rbList.Items))
		return false, nil
	}

	// Also check cluster-scoped resources
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := c.List(ctx, crbList,
		client.MatchingLabels{"rbac.k8s.lab/managed-by": "vulnerable-lab"}); err != nil {
		return false, fmt.Errorf("failed to list lab-managed ClusterRoleBindings: %w", err)
	}
	if len(crbList.Items) > 0 {
		logger.Info("K03 vulnerability still active: lab-managed ClusterRoleBindings still present", "target", targetDeployment)
		return false, nil
	}

	logger.Info("K03 vulnerability remediated: overpermissive RBAC resources removed", "target", targetDeployment)
	return true, nil
}

// checkK07 verifies if the network segmentation vulnerability has been addressed
func checkK07(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// Only one sub-issue: user-service-network-policy removal
	netpol := &networkingv1.NetworkPolicy{}
	if err := c.Get(ctx, client.ObjectKey{Name: "user-service-network-policy", Namespace: namespace}, netpol); errors.IsNotFound(err) {
		logger.Info("K07 vulnerability still active: user-service network policy missing", "target", targetDeployment)
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to check network policy: %w", err)
	}

	logger.Info("K07 vulnerability remediated", "target", targetDeployment, "subIssue", subIssue)
	return true, nil
}

// checkK08 verifies if the secrets management vulnerability has been fixed
// Only sub-issue 0 (secrets in ConfigMap) is supported
func checkK08(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	configMapList := &corev1.ConfigMapList{}
	if err := c.List(ctx, configMapList, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("failed to list ConfigMaps: %w", err)
	}
	if foundSecretInConfigMaps(configMapList.Items, targetDeployment) {
		logger.Info("K08 vulnerability still active: secrets found in ConfigMap", "target", targetDeployment)
		return false, nil
	}

	logger.Info("K08 vulnerability remediated", "target", targetDeployment, "subIssue", subIssue)
	return true, nil
}

func foundSecretInConfigMaps(items []corev1.ConfigMap, targetDeployment string) bool {
	for _, cm := range items {
		if strings.Contains(cm.Name, targetDeployment) {
			for key, value := range cm.Data {
				if isSecretData(key, value) {
					return true
				}
			}
		}
	}
	return false
}

// isSecretData checks if a key-value pair contains secret-like data
func isSecretData(key, value string) bool {
	secretKeys := []string{
		"jwt-secret", "redis-password", "database-url", "api-key",
		"password", "secret", "key", "token", "auth",
	}

	keyLower := strings.ToLower(key)
	for _, secretKey := range secretKeys {
		if strings.Contains(keyLower, secretKey) {
			return len(value) > 5 // Assume secrets are longer than 5 chars
		}
	}

	return false
}
