package breaker

import (
	"context"
	"fmt"
	"math/rand"
	"time"

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
	apiDeploymentName = "api"
)

// Constants for commonly used strings
const (
	paymentAPIKeySecret = "payment-api-key"
	testAPIKey          = "sk_test_12345"
)

// BreakCluster applies the specified vulnerability to the cluster using build-with-vulnerabilities approach
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, targetResource, namespace string, subIssue *int, rng *rand.Rand) (int, error) {
	logger := log.FromContext(ctx)

	logger.Info("Applying vulnerability", "vulnerability", vulnerabilityID, "namespace", namespace)

	// First, ensure the namespace exists
	if err := createNamespaceIfNotExists(ctx, c, namespace); err != nil {
		return 0, fmt.Errorf("failed to create namespace: %w", err)
	}

	// Get the baseline application stack
	appStack := baseline.GetAppStack(namespace)

	// Capture the baseline stack resource keys before mutation so we can detect removals
	baselineKeys := make(map[string]client.Object, len(appStack))
	for _, obj := range appStack {
		key := fmt.Sprintf("%T/%s/%s", obj, obj.GetNamespace(), obj.GetName())
		baselineKeys[key] = obj
	}

	// Apply the vulnerability to the target resource within the stack before deployment
	var chosenSubIssue int
	switch vulnerabilityID {
	case "K01":
		sub, err := applyK01ToStack(appStack, targetResource, subIssue, rng)
		if err != nil {
			return 0, fmt.Errorf("failed to apply K01 vulnerability: %w", err)
		}
		chosenSubIssue = sub
	case "K03":
		sub, err := applyK03ToStack(&appStack, targetResource, namespace, subIssue, rng)
		if err != nil {
			return 0, fmt.Errorf("failed to apply K03 vulnerability: %w", err)
		}
		chosenSubIssue = sub
	// K04 (Lack of Centralized Policy Enforcement) and K05 (Inadequate Logging and Monitoring)
	// are not implemented as they require external infrastructure (OPA Gatekeeper, SIEM systems)
	// rather than resource-level misconfigurations that can be demonstrated in this lab environment
	case "K07":
		sub, err := applyK07ToStack(&appStack, targetResource, namespace, subIssue, rng)
		if err != nil {
			return 0, fmt.Errorf("failed to apply K07 vulnerability: %w", err)
		}
		chosenSubIssue = sub
	case "K08":
		sub, err := applyK08ToStack(&appStack, targetResource, namespace, subIssue, rng)
		if err != nil {
			return 0, fmt.Errorf("failed to apply K08 vulnerability: %w", err)
		}
		chosenSubIssue = sub
	// K09 (Misconfigured Cluster Components) and K10 (Outdated and Vulnerable Kubernetes Components)
	// are not implemented as they require cluster-level administrative access and would affect
	// the entire cluster rather than being contained within individual lab namespaces
	default:
		return 0, fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}

	// Deploy the entire modified stack at once
	for _, obj := range appStack {
		if err := c.Create(ctx, obj); err != nil {
			if errors.IsAlreadyExists(err) {
				// Resource exists — update it with the vulnerable spec
				// Fetch the existing resource to get its resourceVersion
				existing := obj.DeepCopyObject().(client.Object)
				if err := c.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
					return 0, fmt.Errorf("failed to get existing resource %s: %w", obj.GetName(), err)
				}
				// Copy resourceVersion to our modified object
				obj.SetResourceVersion(existing.GetResourceVersion())
				// Preserve immutable fields before update
				preserveImmutableFields(obj, existing)
				// Force new ReplicaSet creation on Deployments to avoid stale RS state
				stampDeploymentRestart(obj)
				if err := c.Update(ctx, obj); err != nil {
					return 0, fmt.Errorf("failed to update existing resource %s: %w", obj.GetName(), err)
				}
				continue
			}
			return 0, fmt.Errorf("failed to create resource %s: %w", obj.GetName(), err)
		}
	}

	// Delete any baseline resources that were intentionally removed by the vulnerability function.
	// For example, K07:0 removes NetworkPolicies from the stack to demonstrate missing network
	// controls — those resources must also be deleted from the cluster if they already exist.
	modifiedKeys := make(map[string]struct{}, len(appStack))
	for _, obj := range appStack {
		key := fmt.Sprintf("%T/%s/%s", obj, obj.GetNamespace(), obj.GetName())
		modifiedKeys[key] = struct{}{}
	}
	for key, obj := range baselineKeys {
		if _, stillPresent := modifiedKeys[key]; !stillPresent {
			existing := obj.DeepCopyObject().(client.Object)
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), existing); err != nil {
				if !errors.IsNotFound(err) {
					return 0, fmt.Errorf("failed to check removed resource %s: %w", obj.GetName(), err)
				}
				// Not found — nothing to delete
				continue
			}
			if err := c.Delete(ctx, existing); err != nil && !errors.IsNotFound(err) {
				return 0, fmt.Errorf("failed to delete removed resource %s: %w", obj.GetName(), err)
			}
			logger.Info("Deleted baseline resource removed by vulnerability", "resource", obj.GetName(), "type", fmt.Sprintf("%T", obj))
		}
	}

	// Clean up lab-managed ConfigMaps from previous vulnerability runs (e.g., K08)
	cmList := &corev1.ConfigMapList{}
	if err := c.List(ctx, cmList, client.InNamespace(namespace),
		client.MatchingLabels{"lab.security.lab/managed-by": "vulnerable-lab"}); err == nil {
		for i := range cmList.Items {
			key := fmt.Sprintf("%T/%s/%s", &cmList.Items[i], cmList.Items[i].Namespace, cmList.Items[i].Name)
			if _, stillPresent := modifiedKeys[key]; !stillPresent {
				if err := c.Delete(ctx, &cmList.Items[i]); err != nil && !errors.IsNotFound(err) {
					return 0, fmt.Errorf("failed to delete orphaned ConfigMap %s: %w", cmList.Items[i].Name, err)
				}
				logger.Info("Deleted orphaned ConfigMap from previous vulnerability", "configmap", cmList.Items[i].Name)
			}
		}
	}

	logger.Info("Vulnerable stack deployment complete", "vulnerability", vulnerabilityID, "target", targetResource)
	return chosenSubIssue, nil
}

// stampDeploymentRestart adds a restart annotation to a Deployment's pod template,
// forcing the Deployment controller to create a new ReplicaSet on every Update.
// This prevents stale RS state where the RS controller has already "observed" the
// desired replica count but never created pods (a known issue with RS reuse after
// repeated rapid updates).
func stampDeploymentRestart(obj client.Object) {
	dep, ok := obj.(*appsv1.Deployment)
	if !ok {
		return
	}
	if dep.Spec.Template.Annotations == nil {
		dep.Spec.Template.Annotations = make(map[string]string)
	}
	dep.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
}

// preserveImmutableFields copies immutable fields from existing resource to new resource before update
func preserveImmutableFields(obj, existing client.Object) {
	switch newObj := obj.(type) {
	case *corev1.Service:
		existingSvc := existing.(*corev1.Service)
		newObj.Spec.ClusterIP = existingSvc.Spec.ClusterIP
		newObj.Spec.ClusterIPs = existingSvc.Spec.ClusterIPs
	}
}

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

// applyK01ToStack modifies the baseline stack to apply insecure workload configurations
// Sub-issues: 0=Privileged(C-0057), 1=Non-root(C-0013), 2=HostPID/IPC(C-0038), 3=HostNetwork(C-0041), 4=HostPath(C-0048)
func applyK01ToStack(appStack []client.Object, targetDeployment string, subIssue *int, rng *rand.Rand) (int, error) {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Choose vulnerability type based on subIssue parameter or randomly
			var vulnType int
			if subIssue != nil {
				if *subIssue < 0 || *subIssue > 4 {
					return 0, fmt.Errorf("subIssue %d out of range for K01 (valid: 0-4)", *subIssue)
				}
				vulnType = *subIssue
			} else {
				// Randomly choose one of five K01 vulnerability types
				vulnType = rng.Intn(5)
			}

			switch vulnType {
			case 0: // Privileged container (C-0057)
				// Preserve existing security context but add privileged vulnerability
				if container.SecurityContext == nil {
					container.SecurityContext = &corev1.SecurityContext{}
				}
				container.SecurityContext.Privileged = ptr.To(true)
				// When privileged=true, allowPrivilegeEscalation must be nil or true (cannot be false)
				container.SecurityContext.AllowPrivilegeEscalation = nil
				// Clear capabilities drop: leaving Drop=["ALL"] suppresses kubescape C-0057
				if container.SecurityContext.Capabilities != nil {
					container.SecurityContext.Capabilities.Drop = nil
				}
				// Add annotation indicating why this is privileged (looks realistic)
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.privileged"] = "host-access-required"

			case 1: // Running as root (C-0013)
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

			case 2: // Host PID/IPC access (C-0038)
				dep.Spec.Template.Spec.HostPID = true
				dep.Spec.Template.Spec.HostIPC = true

			case 3: // HostNetwork access (C-0041)
				dep.Spec.Template.Spec.HostNetwork = true

			case 4: // HostPath volume mount (C-0048)
				dep.Spec.Template.Spec.Volumes = append(dep.Spec.Template.Spec.Volumes, corev1.Volume{
					Name: "host-data",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"},
					},
				})
				dep.Spec.Template.Spec.Containers[0].VolumeMounts = append(
					dep.Spec.Template.Spec.Containers[0].VolumeMounts,
					corev1.VolumeMount{
						Name:      "host-data",
						MountPath: "/host-log",
						ReadOnly:  true,
					},
				)
			}

			return vulnType, nil
		}
	}

	return 0, fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK03ToStack modifies the baseline stack to apply overly permissive RBAC configurations
// Sub-issues: 0=C-0015(secrets list), 1=C-0188(pod create), 2=C-0007(delete), 3=C-0035(admin escalation),
//
//	4=C-0187(wildcard), 5=C-0063(portforward), 6=C-0002(exec)
func applyK03ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) (int, error) {
	// Find and modify the target deployment within the stack
	for _, obj := range *appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Choose vulnerability type based on subIssue parameter or randomly
			var vulnType int
			if subIssue != nil {
				if *subIssue < 0 || *subIssue > 6 {
					return 0, fmt.Errorf("subIssue %d out of range for K03 (valid: 0-6)", *subIssue)
				}
				vulnType = *subIssue
			} else {
				// Randomly choose one of seven K03 vulnerability types
				vulnType = rng.Intn(7)
			}

			switch vulnType {
			case 0: // List Kubernetes secrets (C-0015)
				createSecretsAccessRBAC(appStack, namespace)
			case 1: // Create pods (C-0188)
				createPodCreationRBAC(appStack, namespace)
			case 2: // Delete capabilities (C-0007)
				createDeleteCapabilitiesRBAC(appStack, namespace)
			case 3: // Administrative Roles (C-0035)
				createAdminRoleEscalation(appStack, namespace)
			case 4: // Wildcard use in Roles (C-0187)
				createWildcardRBAC(appStack, namespace)
			case 5: // Portforwarding privileges (C-0063)
				createPortforwardRBAC(appStack, namespace)
			case 6: // Command execution (C-0002)
				createExecRBAC(appStack, namespace)
			}

			// dep is used to satisfy the loop; mark it as used
			_ = dep
			return vulnType, nil
		}
	}

	return 0, fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// createSecretsAccessRBAC grants read access to secrets within the namespace (C-0015)
func createSecretsAccessRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secrets-access-role", namespace),
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
				Verbs:     []string{"list", "watch", "get"}, // Can list all secrets in namespace
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secrets-access-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createWildcardRBAC grants wildcard permissions within the namespace (C-0187)
func createWildcardRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-wildcard-role", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "broad-access-required",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"get"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-wildcard-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createPortforwardRBAC grants pods/portforward permissions (C-0063)
func createPortforwardRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-portforward-role", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "debug-access",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/portforward"},
				Verbs:     []string{"create", "get"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-portforward-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createExecRBAC grants pods/exec permissions (C-0002)
func createExecRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-exec-role", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "debug-access",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create", "get"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-exec-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createDeleteCapabilitiesRBAC grants broad delete permissions within the namespace (C-0007)
func createDeleteCapabilitiesRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-delete-role", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "cleanup-operations",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "configmaps"},
				Verbs:     []string{"delete"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-delete-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createPodCreationRBAC grants pod creation permissions within the namespace (C-0188)
func createPodCreationRBAC(appStack *[]client.Object, namespace string) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pod-create-role", namespace),
			Namespace: namespace,
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "workload-management",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create", "get", "list", "watch"},
			},
		},
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-pod-create-binding", namespace),
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

	*appStack = append(*appStack, role, binding)
}

// createAdminRoleEscalation creates a ClusterRole with privilege escalation ability (C-0035)
func createAdminRoleEscalation(appStack *[]client.Object, namespace string) {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-admin-escalation-role", namespace),
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
				"rbac.k8s.lab/namespace":  namespace,
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "infrastructure-management",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles", "roles"},
				Verbs:     []string{"bind", "escalate"},
			},
		},
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-admin-escalation-binding", namespace),
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
				"rbac.k8s.lab/namespace":  namespace,
			},
			Annotations: map[string]string{
				"rbac.authorization.k8s.io/reason": "infrastructure-management",
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
			Name:     clusterRole.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	*appStack = append(*appStack, clusterRole, binding)
}

// applyK07ToStack modifies the baseline stack to demonstrate missing network segmentation controls
// Sub-issue 0: Remove user-service network policy (C-0260, count=1)
//
//nolint:unparam // namespace kept for consistency with other applyKXX functions
func applyK07ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) (int, error) {
	// K07 vulnerabilities are about MISSING network controls rather than broken ones
	// Note: targetDeployment parameter kept for API consistency with other vulnerability functions
	_ = targetDeployment

	// Choose vulnerability type based on subIssue parameter or randomly
	var vulnType int
	if subIssue != nil {
		if *subIssue < 0 || *subIssue > 0 {
			return 0, fmt.Errorf("subIssue %d out of range for K07 (valid: 0)", *subIssue)
		}
		vulnType = *subIssue
	} else {
		// Only one K07 vulnerability type
		vulnType = 0
	}

	switch vulnType {
	case 0: // Backend microservice network policy removed (flagged by Kubescape C-0260)
		removeNamedNetworkPolicies(appStack, "user-service-network-policy")
	}

	return vulnType, nil
}

// removeNamedNetworkPolicies removes specific NetworkPolicies from the stack by name
func removeNamedNetworkPolicies(appStack *[]client.Object, names ...string) {
	nameSet := make(map[string]struct{}, len(names))
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	updatedStack := make([]client.Object, 0, len(*appStack))
	for _, obj := range *appStack {
		if np, ok := obj.(*networkingv1.NetworkPolicy); ok {
			if _, remove := nameSet[np.Name]; remove {
				continue
			}
		}
		updatedStack = append(updatedStack, obj)
	}
	*appStack = updatedStack
}

// applyK08ToStack modifies the baseline stack to apply secrets management vulnerabilities
// Sub-issue 0: Secret data in ConfigMaps (C-0012)
//
//nolint:unparam // rng kept for API consistency with other applyKXX functions
func applyK08ToStack(appStack *[]client.Object, targetDeployment, namespace string, subIssue *int, rng *rand.Rand) (int, error) {
	// Choose vulnerability type based on subIssue parameter or randomly
	var vulnType int
	if subIssue != nil {
		if *subIssue < 0 || *subIssue > 0 {
			return 0, fmt.Errorf("subIssue %d out of range for K08 (valid: 0)", *subIssue)
		}
		vulnType = *subIssue
	} else {
		// Only one K08 vulnerability type
		vulnType = 0
	}

	switch vulnType {
	case 0: // Secret data in ConfigMaps
		moveSecretsToConfigMap(appStack, targetDeployment, namespace)
	}

	return vulnType, nil
}

// moveSecretsToConfigMap creates a ConfigMap with secret data instead of using Secrets
func moveSecretsToConfigMap(appStack *[]client.Object, targetDeployment, namespace string) {
	// Create a ConfigMap with sensitive data
	insecureConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-config", targetDeployment),
			Namespace: namespace,
			Labels: map[string]string{
				"lab.security.lab/managed-by": "vulnerable-lab",
			},
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

	// Find the target deployment, add env vars, and insert the ConfigMap immediately after it
	for i, obj := range *appStack {
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
			container.Env = append(container.Env, configEnvs...)

			// Insert ConfigMap right after the deployment in a single pass
			*appStack = append((*appStack)[:i+1], append([]client.Object{insecureConfigMap}, (*appStack)[i+1:]...)...)
			break
		}
	}
}
