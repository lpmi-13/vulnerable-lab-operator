package breaker

import (
	"context"
	"encoding/base64"
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
	case "K06":
		return checkK06(ctx, c, targetResource, namespace, subIssue)
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
//
//nolint:gocyclo // Each switch case tests one isolated condition; complexity is intentional
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
	case 2: // Dangerous capabilities
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == capSysAdmin || cap == capNetAdmin {
					logger.Info("K01 vulnerability still active: dangerous capabilities", "target", targetDeployment, "capability", cap)
					return false, nil
				}
			}
		}
	case 3: // Missing fsGroup in PodSecurityContext
		if dep.Spec.Template.Spec.SecurityContext == nil || dep.Spec.Template.Spec.SecurityContext.FSGroup == nil {
			logger.Info("K01 vulnerability still active: fsGroup missing from PodSecurityContext", "target", targetDeployment)
			return false, nil
		}
	case 4: // ReadOnlyRootFilesystem disabled
		if container.SecurityContext != nil && container.SecurityContext.ReadOnlyRootFilesystem != nil && !*container.SecurityContext.ReadOnlyRootFilesystem {
			logger.Info("K01 vulnerability still active: readOnlyRootFilesystem disabled", "target", targetDeployment)
			return false, nil
		}
	case 5: // Missing resource limits
		if len(container.Resources.Limits) == 0 {
			logger.Info("K01 vulnerability still active: missing resource limits", "target", targetDeployment)
			return false, nil
		}
	case 6: // Host PID/IPC access
		if dep.Spec.Template.Spec.HostPID || dep.Spec.Template.Spec.HostIPC {
			logger.Info("K01 vulnerability still active: hostPID/hostIPC enabled", "target", targetDeployment)
			return false, nil
		}
	case 7: // HostNetwork access
		if dep.Spec.Template.Spec.HostNetwork {
			logger.Info("K01 vulnerability still active: hostNetwork enabled", "target", targetDeployment)
			return false, nil
		}
	case 8: // HostPath volume mount
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
		if container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == capSysAdmin || cap == capNetAdmin {
					logger.Info("K01 vulnerability still active: dangerous capabilities", "target", targetDeployment, "capability", cap)
					return false, nil
				}
			}
		}
		if container.SecurityContext.ReadOnlyRootFilesystem != nil && !*container.SecurityContext.ReadOnlyRootFilesystem {
			logger.Info("K01 vulnerability still active: readOnlyRootFilesystem disabled", "target", targetDeployment)
			return false, nil
		}
	}
	if dep.Spec.Template.Spec.SecurityContext == nil || dep.Spec.Template.Spec.SecurityContext.FSGroup == nil {
		logger.Info("K01 vulnerability still active: fsGroup missing from PodSecurityContext", "target", targetDeployment)
		return false, nil
	}
	if len(container.Resources.Limits) == 0 {
		logger.Info("K01 vulnerability still active: missing resource limits", "target", targetDeployment)
		return false, nil
	}
	logger.Info("K01 vulnerability remediated: security context is now secure", "target", targetDeployment)
	return true, nil
}

// checkK02 verifies if the supply chain vulnerability has been fixed by checking image versions
// checkK03 verifies if the RBAC vulnerability has been fixed
//
//nolint:gocyclo // Each switch case checks one isolated RBAC resource; complexity is intentional
func checkK03(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// If a specific sub-issue was applied, check only that one
	if subIssue != nil {
		switch *subIssue {
		case 0: // Namespace overpermissive role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-overpermissive", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: overpermissive role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check overpermissive role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-overpermissive-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: overpermissive binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check overpermissive binding: %w", err)
			}
		case 1: // Default SA permissions role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-default-permissions", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: default SA permissions role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check default permissions role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-default-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: default SA binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check default SA binding: %w", err)
			}
		case 2: // Secrets reader role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-secrets-reader", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: secrets reader role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check secrets reader role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-secrets-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: secrets binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check secrets binding: %w", err)
			}
		case 3: // Cluster-admin binding
			clusterBinding := &rbacv1.ClusterRoleBinding{}
			clusterBindingName := fmt.Sprintf("%s-cluster-admin-binding", namespace)
			if err := c.Get(ctx, client.ObjectKey{Name: clusterBindingName}, clusterBinding); err == nil {
				logger.Info("K03 vulnerability still active: cluster-admin binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check ClusterRoleBinding %s: %w", clusterBindingName, err)
			}
		case 4: // Wildcard permissions role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-wildcard-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: wildcard role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check wildcard role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-wildcard-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: wildcard binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check wildcard binding: %w", err)
			}
		case 5: // exec + portforward role + binding
			role := &rbacv1.Role{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-exec-portforward-role", namespace), Namespace: namespace}, role); err == nil {
				logger.Info("K03 vulnerability still active: exec/portforward role exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check exec/portforward role: %w", err)
			}
			binding := &rbacv1.RoleBinding{}
			if err := c.Get(ctx, client.ObjectKey{Name: fmt.Sprintf("%s-exec-portforward-binding", namespace), Namespace: namespace}, binding); err == nil {
				logger.Info("K03 vulnerability still active: exec/portforward binding exists", "target", targetDeployment)
				return false, nil
			} else if !errors.IsNotFound(err) {
				return false, fmt.Errorf("failed to check exec/portforward binding: %w", err)
			}
		case 6: // Delete capabilities role + binding
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
		case 7: // Pod creation role + binding
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
		}
		logger.Info("K03 vulnerability remediated", "target", targetDeployment, "subIssue", *subIssue)
		return true, nil
	}

	// Fallback: check all sub-issues (backward compat when subIssue is nil)
	overpermissiveResources := []struct {
		resource  client.Object
		name      string
		namespace string
		reason    string
	}{
		// Namespace Overpermissive Access (subIssue 0)
		{&rbacv1.Role{}, fmt.Sprintf("%s-overpermissive", namespace), namespace, "overpermissive role"},
		{&rbacv1.RoleBinding{}, fmt.Sprintf("%s-overpermissive-binding", namespace), namespace, "overpermissive binding"},
		// Default Service Account Permissions (subIssue 1)
		{&rbacv1.Role{}, fmt.Sprintf("%s-default-permissions", namespace), namespace, "default SA permissions role"},
		{&rbacv1.RoleBinding{}, fmt.Sprintf("%s-default-binding", namespace), namespace, "default SA binding"},
		// Excessive Secrets Access (subIssue 2)
		{&rbacv1.Role{}, fmt.Sprintf("%s-secrets-reader", namespace), namespace, "secrets reader role"},
		{&rbacv1.RoleBinding{}, fmt.Sprintf("%s-secrets-binding", namespace), namespace, "secrets binding"},
	}

	vulnerabilityFound := false
	for _, res := range overpermissiveResources {
		key := client.ObjectKey{Name: res.name, Namespace: res.namespace}

		err := c.Get(ctx, key, res.resource)
		if err == nil {
			// Resource still exists - vulnerability is active
			logger.Info("K03 vulnerability still active", "target", targetDeployment,
				"resource", res.name, "reason", res.reason)
			vulnerabilityFound = true
			break // Found one vulnerability, that's enough to know it's not remediated
		} else if !errors.IsNotFound(err) {
			// Unexpected error
			return false, fmt.Errorf("failed to check RBAC resource %s: %w", res.name, err)
		}
		// Resource not found is good - continue checking
	}

	// Check for ClusterRoleBinding to cluster-admin (subIssue 3)
	clusterBinding := &rbacv1.ClusterRoleBinding{}
	clusterBindingName := fmt.Sprintf("%s-cluster-admin-binding", namespace)
	err := c.Get(ctx, client.ObjectKey{Name: clusterBindingName}, clusterBinding)
	if err == nil {
		logger.Info("K03 vulnerability still active", "target", targetDeployment,
			"resource", clusterBindingName, "reason", "cluster-admin binding")
		vulnerabilityFound = true
	} else if !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to check ClusterRoleBinding %s: %w", clusterBindingName, err)
	}

	if vulnerabilityFound {
		return false, nil
	}

	logger.Info("K03 vulnerability remediated: overpermissive RBAC resources removed", "target", targetDeployment)
	return true, nil
}

// checkK06 verifies if the authentication vulnerability has been fixed
func checkK06(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K06 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	// If a specific sub-issue was applied, check only that one
	if subIssue != nil {
		switch *subIssue {
		case 0: // Default service account usage (empty serviceAccountName)
			if dep.Spec.Template.Spec.ServiceAccountName == "" {
				logger.Info("K06 vulnerability still active: using default service account", "target", targetDeployment)
				return false, nil
			}
		case 1: // Auto-mount service account token
			if dep.Spec.Template.Spec.AutomountServiceAccountToken != nil && *dep.Spec.Template.Spec.AutomountServiceAccountToken {
				logger.Info("K06 vulnerability still active: service account token auto-mounting enabled", "target", targetDeployment)
				return false, nil
			}
		case 2: // Unrestricted SA with automount
			if dep.Spec.Template.Spec.ServiceAccountName != "" && dep.Spec.Template.Spec.ServiceAccountName != "default" {
				sa := &corev1.ServiceAccount{}
				if err := c.Get(ctx, client.ObjectKey{Name: dep.Spec.Template.Spec.ServiceAccountName, Namespace: namespace}, sa); err == nil {
					if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
						logger.Info("K06 vulnerability still active: non-standard service account with automount enabled",
							"target", targetDeployment,
							"serviceAccount", dep.Spec.Template.Spec.ServiceAccountName)
						return false, nil
					}
				}
			}
		}
		logger.Info("K06 vulnerability remediated", "target", targetDeployment, "subIssue", *subIssue)
		return true, nil
	}

	// Fallback: check all sub-issues (backward compat when subIssue is nil)
	vulnerabilitiesFound := false

	// Check for default service account usage (empty serviceAccountName) - K06:0
	if dep.Spec.Template.Spec.ServiceAccountName == "" {
		logger.Info("K06 vulnerability still active: using default service account", "target", targetDeployment)
		vulnerabilitiesFound = true
	}

	// Check for auto-mounted service account tokens - K06:1
	if dep.Spec.Template.Spec.AutomountServiceAccountToken != nil && *dep.Spec.Template.Spec.AutomountServiceAccountToken {
		logger.Info("K06 vulnerability still active: service account token auto-mounting enabled", "target", targetDeployment)
		vulnerabilitiesFound = true
	}

	// Check for non-standard service account with automount enabled - K06:2
	if dep.Spec.Template.Spec.ServiceAccountName != "" && dep.Spec.Template.Spec.ServiceAccountName != "default" {
		// Check if this SA exists and has automount enabled
		sa := &corev1.ServiceAccount{}
		if err := c.Get(ctx, client.ObjectKey{Name: dep.Spec.Template.Spec.ServiceAccountName, Namespace: namespace}, sa); err == nil {
			// SA exists, check if automount is enabled
			if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
				logger.Info("K06 vulnerability still active: non-standard service account with automount enabled",
					"target", targetDeployment,
					"serviceAccount", dep.Spec.Template.Spec.ServiceAccountName)
				vulnerabilitiesFound = true
			}
		}
	}

	if vulnerabilitiesFound {
		return false, nil
	}

	logger.Info("K06 vulnerability remediated: authentication configuration is now secure", "target", targetDeployment)
	return true, nil
}

// checkK07 verifies if the network segmentation vulnerability has been addressed
func checkK07(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	if subIssue != nil {
		return checkK07BySubIssue(ctx, c, targetDeployment, namespace, *subIssue)
	}
	return checkK07All(ctx, c, targetDeployment, namespace)
}

// checkK07BySubIssue checks only the specific K07 sub-issue that was applied
//
//nolint:gocyclo // Each switch case tests one isolated network condition; complexity is intentional
func checkK07BySubIssue(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue int) (bool, error) {
	logger := log.FromContext(ctx)
	switch subIssue {
	case 0: // Missing NetworkPolicy (api-network-policy was deleted)
		netpol := &networkingv1.NetworkPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: "api-network-policy", Namespace: namespace}, netpol); errors.IsNotFound(err) {
			logger.Info("K07 vulnerability still active: network policy missing", "target", targetDeployment)
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("failed to check network policy: %w", err)
		}
	case 1: // Allow-all NetworkPolicy exists
		allowAllPolicy := &networkingv1.NetworkPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: "allow-all-traffic", Namespace: namespace}, allowAllPolicy); err == nil {
			logger.Info("K07 vulnerability still active: allow-all network policy exists", "target", targetDeployment)
			return false, nil
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("failed to check allow-all policy: %w", err)
		}
	case 2: // Postgres service exposed as NodePort
		postgresSvc := &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKey{Name: "postgres-service", Namespace: namespace}, postgresSvc); err == nil {
			if postgresSvc.Spec.Type == corev1.ServiceTypeNodePort {
				logger.Info("K07 vulnerability still active: postgres service exposed as NodePort", "target", targetDeployment)
				return false, nil
			}
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("failed to check postgres service: %w", err)
		}
	case 3: // Postgres service exposed as LoadBalancer
		postgresSvc := &corev1.Service{}
		if err := c.Get(ctx, client.ObjectKey{Name: "postgres-service", Namespace: namespace}, postgresSvc); err == nil {
			if postgresSvc.Spec.Type == corev1.ServiceTypeLoadBalancer {
				logger.Info("K07 vulnerability still active: postgres service exposed as LoadBalancer", "target", targetDeployment)
				return false, nil
			}
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("failed to check postgres service: %w", err)
		}
	case 4: // Overly permissive egress in network policy
		netpol := &networkingv1.NetworkPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Name: "api-network-policy", Namespace: namespace}, netpol); err == nil {
			for _, egress := range netpol.Spec.Egress {
				if len(egress.To) == 0 {
					logger.Info("K07 vulnerability still active: overly permissive egress in network policy", "target", targetDeployment)
					return false, nil
				}
			}
		} else if !errors.IsNotFound(err) {
			return false, fmt.Errorf("failed to check network policy egress: %w", err)
		}
	}
	logger.Info("K07 vulnerability remediated", "target", targetDeployment, "subIssue", subIssue)
	return true, nil
}

// checkK07All checks all K07 sub-issues (fallback when no specific sub-issue is known)
func checkK07All(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)
	vulnerabilitiesFound := false

	netpol := &networkingv1.NetworkPolicy{}
	err := c.Get(ctx, client.ObjectKey{Name: "api-network-policy", Namespace: namespace}, netpol)
	if errors.IsNotFound(err) {
		logger.Info("K07 vulnerability still active: network policy missing", "target", targetDeployment)
		vulnerabilitiesFound = true
	} else if err != nil {
		return false, fmt.Errorf("failed to check network policy: %w", err)
	}

	allowAllPolicy := &networkingv1.NetworkPolicy{}
	err = c.Get(ctx, client.ObjectKey{Name: "allow-all-traffic", Namespace: namespace}, allowAllPolicy)
	if err == nil {
		logger.Info("K07 vulnerability still active: allow-all network policy exists", "target", targetDeployment)
		vulnerabilitiesFound = true
	} else if !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to check allow-all policy: %w", err)
	}

	postgresSvc := &corev1.Service{}
	err = c.Get(ctx, client.ObjectKey{Name: "postgres-service", Namespace: namespace}, postgresSvc)
	if err == nil {
		if postgresSvc.Spec.Type == corev1.ServiceTypeNodePort {
			logger.Info("K07 vulnerability still active: postgres service exposed as NodePort", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
		if postgresSvc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			logger.Info("K07 vulnerability still active: postgres service exposed as LoadBalancer", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
	} else if !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to check postgres service: %w", err)
	}

	if netpol != nil && netpol.Name != "" {
		for _, egress := range netpol.Spec.Egress {
			if len(egress.To) == 0 {
				logger.Info("K07 vulnerability still active: overly permissive egress in network policy", "target", targetDeployment)
				vulnerabilitiesFound = true
				break
			}
		}
	}

	if vulnerabilitiesFound {
		return false, nil
	}
	logger.Info("K07 vulnerability remediated: network segmentation controls are in place", "target", targetDeployment)
	return true, nil
}

// checkK08 verifies if the secrets management vulnerability has been fixed
func checkK08(ctx context.Context, c client.Client, targetDeployment, namespace string, subIssue *int) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment to check for hardcoded secrets and insecure configurations
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K08 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	container := dep.Spec.Template.Spec.Containers[0]

	// If a specific sub-issue was applied, check only that one
	if subIssue != nil {
		switch *subIssue {
		case 0: // Secrets in ConfigMap
			configMapList := &corev1.ConfigMapList{}
			if err = c.List(ctx, configMapList, client.InNamespace(namespace)); err != nil {
				return false, fmt.Errorf("failed to list ConfigMaps: %w", err)
			}
			if foundSecretInConfigMaps(configMapList.Items, targetDeployment) {
				logger.Info("K08 vulnerability still active: secrets found in ConfigMap", "target", targetDeployment)
				return false, nil
			}
		case 1: // Hardcoded env secrets
			if hasHardcodedEnvSecrets(container.Env) {
				logger.Info("K08 vulnerability still active: hardcoded secret found", "target", targetDeployment)
				return false, nil
			}
		case 2: // Insecure volume permissions
			if hasInsecureVolumePermissions(dep.Spec.Template.Spec.Volumes) {
				logger.Info("K08 vulnerability still active: insecure secret volume permissions", "target", targetDeployment)
				return false, nil
			}
		case 3: // Secret annotations
			if hasSecretAnnotations(dep.Spec.Template.Annotations) {
				logger.Info("K08 vulnerability still active: secret data in pod annotations", "target", targetDeployment)
				return false, nil
			}
		}
		logger.Info("K08 vulnerability remediated", "target", targetDeployment, "subIssue", *subIssue)
		return true, nil
	}

	// Fallback: check all sub-issues (backward compat when subIssue is nil)
	if hasHardcodedEnvSecrets(container.Env) {
		logger.Info("K08 vulnerability still active: hardcoded secret found", "target", targetDeployment)
		return false, nil
	}

	if hasInsecureVolumePermissions(dep.Spec.Template.Spec.Volumes) {
		logger.Info("K08 vulnerability still active: insecure secret volume permissions", "target", targetDeployment)
		return false, nil
	}

	if hasSecretAnnotations(dep.Spec.Template.Annotations) {
		logger.Info("K08 vulnerability still active: secret data in pod annotations", "target", targetDeployment)
		return false, nil
	}

	// Check for secrets stored in ConfigMaps
	configMapList := &corev1.ConfigMapList{}
	if err = c.List(ctx, configMapList, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("failed to list ConfigMaps: %w", err)
	}
	if foundSecretInConfigMaps(configMapList.Items, targetDeployment) {
		logger.Info("K08 vulnerability still active: secrets found in ConfigMap", "target", targetDeployment)
		return false, nil
	}

	// Check for base64 exposed secrets
	secretList := &corev1.SecretList{}
	if err = c.List(ctx, secretList, client.InNamespace(namespace)); err != nil {
		return false, fmt.Errorf("failed to list Secrets: %w", err)
	}
	if foundBase64ExposedSecrets(secretList.Items) {
		logger.Info("K08 vulnerability still active: base64 exposed secret", "target", targetDeployment)
		return false, nil
	}

	logger.Info("K08 vulnerability remediated: secrets management is now secure", "target", targetDeployment)
	return true, nil
}

func hasHardcodedEnvSecrets(envVars []corev1.EnvVar) bool {
	for _, env := range envVars {
		if env.ValueFrom == nil && env.Value != "" && isHardcodedSecret(env.Name, env.Value) {
			return true
		}
	}
	return false
}

func hasInsecureVolumePermissions(volumes []corev1.Volume) bool {
	for _, volume := range volumes {
		if volume.Secret != nil && volume.Secret.DefaultMode != nil {
			if *volume.Secret.DefaultMode&0077 != 0 {
				return true
			}
		}
	}
	return false
}

func hasSecretAnnotations(annotations map[string]string) bool {
	if annotations == nil {
		return false
	}
	secretAnnotationPatterns := []string{"jwt-secret", "api-key", "password", "token", "secret"}
	for key, value := range annotations {
		if len(value) == 0 {
			continue
		}
		for _, pattern := range secretAnnotationPatterns {
			if strings.Contains(strings.ToLower(key), pattern) {
				return true
			}
		}
	}
	return false
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

func foundBase64ExposedSecrets(items []corev1.Secret) bool {
	for _, secret := range items {
		if secret.StringData == nil && secret.Data != nil {
			for key, data := range secret.Data {
				if decoded, err := base64.StdEncoding.DecodeString(string(data)); err == nil {
					if isSecretData(key, string(decoded)) {
						return true
					}
				}
			}
		}
	}
	return false
}

// isHardcodedSecret checks if an environment variable contains a hardcoded secret
func isHardcodedSecret(name, value string) bool {
	// Check for common secret patterns
	secretPatterns := map[string][]string{
		"JWT_SECRET":     {"super-secure-jwt-signing-key-2024"},
		"REDIS_PASSWORD": {"redis-secure-password-123"},
		"API_KEY":        {"sk_test_12345", "sk_live_"},
	}

	if patterns, exists := secretPatterns[name]; exists {
		for _, pattern := range patterns {
			if strings.Contains(value, pattern) {
				return true
			}
		}
	}

	// Generic secret detection
	if strings.Contains(strings.ToLower(name), "secret") ||
		strings.Contains(strings.ToLower(name), "password") ||
		strings.Contains(strings.ToLower(name), "key") {
		if len(value) > 8 && !strings.Contains(value, ":") { // Avoid URLs
			return true
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
