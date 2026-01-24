package controller

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/lpmi-13/vulnerable-lab-operator/api/v1alpha1"
	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
	"github.com/lpmi-13/vulnerable-lab-operator/internal/breaker"
)

// notificationState tracks the last notification sent for a lab
type notificationState struct {
	lastMessage string
	lastTime    time.Time
}

// VulnerableLabReconciler reconciles a VulnerableLab object
type VulnerableLabReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Deduplication state for notifications
	lastNotified     map[string]*notificationState
	initialSetupSent map[string]bool
	watchTriggered   map[string]bool
	mu               sync.Mutex
}

// +kubebuilder:rbac:groups=lab.security.lab,resources=vulnerablelabs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=lab.security.lab,resources=vulnerablelabs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=lab.security.lab,resources=vulnerablelabs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

func (r *VulnerableLabReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling VulnerableLab", "name", req.Name)

	var lab v1alpha1.VulnerableLab
	if err := r.Get(ctx, req.NamespacedName, &lab); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VulnerableLab resource deleted.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	namespace := req.Name

	// STATE MACHINE
	switch lab.Status.State {
	case "": // First time - initialize
		fallthrough
	case v1alpha1.StateInitialized:
		return r.initializeLab(ctx, &lab, namespace)

	case v1alpha1.StateVulnerable:
		return r.checkRemediation(ctx, &lab, namespace)

	case v1alpha1.StateRemediated:
		return r.resetLab(ctx, &lab, namespace)

	case v1alpha1.StateError:
		return ctrl.Result{}, nil // Don't do anything if in error state

	default:
		logger.Info("Unknown state, resetting to initialized", "state", lab.Status.State)
		if err := r.updateStatusWithRetry(ctx, &lab, func(lab *v1alpha1.VulnerableLab) {
			lab.Status.State = v1alpha1.StateInitialized
		}); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
}

func (r *VulnerableLabReconciler) initializeLab(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Initializing new lab environment", "namespace", namespace)

	// Send initial setup message once per namespace
	r.mu.Lock()
	if r.initialSetupSent == nil {
		r.initialSetupSent = make(map[string]bool)
	}
	if !r.initialSetupSent[namespace] {
		r.mu.Unlock()
		r.writeClusterStatusDedup("Initial cluster setup in progress, please wait...", namespace)
		r.mu.Lock()
		r.initialSetupSent[namespace] = true
	}
	r.mu.Unlock()

	// Choose vulnerability type based on spec or randomly
	// This logic implements three different persistence behaviors across remediation cycles:
	//
	// 1. Complete randomization (vulnerability: "random" or empty):
	//    - Selects a new random category AND sub-issue after each remediation
	//    - Best for general vulnerability identification practice
	//
	// 2. Category persistence (vulnerability: "K03", no subIssue specified):
	//    - Always uses the same category (K03) but selects random sub-issues
	//    - Best for focused practice on a specific vulnerability category
	//    - Spec.Vulnerability persists across resets, Status.ChosenVulnerability gets cleared
	//
	// 3. Complete persistence (vulnerability: "K03", subIssue: 2):
	//    - Always uses the exact same category AND sub-issue after each remediation
	//    - Best for mastering one specific vulnerability through repetitive practice
	//    - Both Spec.Vulnerability and Spec.SubIssue persist across resets
	var chosenVuln string
	if lab.Spec.Vulnerability != "" && lab.Spec.Vulnerability != "random" {
		// Use specified vulnerability category (behavior 2 or 3 above)
		chosenVuln = lab.Spec.Vulnerability
		if lab.Spec.SubIssue != nil {
			// Complete persistence - same category and same sub-issue every time
			logger.Info("Using specified vulnerability category and sub-issue", "vulnerability", chosenVuln, "subIssue", *lab.Spec.SubIssue)
		} else {
			// Category persistence - same category, random sub-issue every time
			logger.Info("Using specified vulnerability category with random sub-issue", "vulnerability", chosenVuln)
		}
	} else {
		// Complete randomization (behavior 1 above)
		// Randomly choose both vulnerability category and sub-issue
		vulnerabilities := []string{"K01", "K02", "K03", "K06", "K07", "K08"}
		vulnIndex := r.selectRandomIndex(len(vulnerabilities))
		chosenVuln = vulnerabilities[vulnIndex]
		if lab.Spec.SubIssue != nil {
			// This is an unusual case: random category but specified sub-issue
			// The sub-issue will persist, but the category will change on each reset
			logger.Info("Randomly selected vulnerability category with specified sub-issue", "vulnerability", chosenVuln, "subIssue", *lab.Spec.SubIssue)
		} else {
			// True complete randomization - both category and sub-issue change
			logger.Info("Randomly selected vulnerability category and sub-issue", "vulnerability", chosenVuln)
		}
	}

	// Choose appropriate targets based on vulnerability type
	var viableTargets []string
	switch chosenVuln {
	case "K01":
		viableTargets = []string{"api", "webapp", "redis-cache", "prometheus", "grafana", "postgres-db", "user-service", "payment-service"}
	case "K02":
		viableTargets = []string{"api", "webapp", "user-service", "payment-service", "grafana"}
	case "K03":
		viableTargets = []string{"api", "user-service", "payment-service"} // Services that need RBAC permissions
	case "K06":
		viableTargets = []string{"api", "user-service", "payment-service"} // Services that use secrets
	case "K07":
		viableTargets = []string{"api", "webapp", "user-service", "payment-service"} // Services affected by network policies
	case "K08":
		viableTargets = []string{"api", "user-service", "payment-service"} // Services that use secrets
	default:
		viableTargets = []string{"api", "webapp"}
	}

	targetIndex := r.selectRandomIndex(len(viableTargets))
	targetDeployment := viableTargets[targetIndex]

	// Use BreakCluster instead of InitializeLab
	if err := breaker.BreakCluster(ctx, r.Client, chosenVuln, targetDeployment, namespace, lab.Spec.SubIssue); err != nil {
		logger.Error(err, "Failed to apply vulnerability")

		// Get the latest version of the resource before updating
		if err := r.Get(ctx, client.ObjectKey{Name: lab.Name, Namespace: lab.Namespace}, lab); err != nil {
			return ctrl.Result{}, err
		}

		if updateErr := r.updateStatusWithRetry(ctx, lab, func(lab *v1alpha1.VulnerableLab) {
			lab.Status.State = v1alpha1.StateError
			lab.Status.Message = "Failed to apply vulnerability: " + err.Error()
		}); updateErr != nil {
			logger.Error(updateErr, "Failed to update error status")
		}
		return ctrl.Result{}, err
	}

	// Get the latest version of the resource before updating
	if err := r.Get(ctx, client.ObjectKey{Name: lab.Name, Namespace: lab.Namespace}, lab); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.updateStatusWithRetry(ctx, lab, func(lab *v1alpha1.VulnerableLab) {
		lab.Status.ChosenVulnerability = chosenVuln
		lab.Status.TargetResource = targetDeployment
		lab.Status.State = v1alpha1.StateVulnerable
		lab.Status.Message = fmt.Sprintf("Cluster is vulnerable. Find and fix issue %s. Target: %s", chosenVuln, targetDeployment)
	}); err != nil {
		logger.Error(err, "Failed to update status after lab initialization")
		return ctrl.Result{}, err
	}

	logger.Info("Lab initialization complete", "vulnerability", chosenVuln, "target", targetDeployment)

	// Update cluster status file for user visibility
	r.writeClusterStatusDedup("Ready for scanning", namespace)

	return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
}

func (r *VulnerableLabReconciler) checkRemediation(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Checking if vulnerability has been remediated", "vulnerability", lab.Status.ChosenVulnerability, "target", lab.Status.TargetResource)

	// For K03 vulnerabilities, check for partial deletions and clean up
	if lab.Status.ChosenVulnerability == "K03" {
		r.cleanupOrphanedK03Resources(ctx, namespace)
	}

	isFixed, err := breaker.CheckRemediation(ctx, r.Client, lab.Status.ChosenVulnerability, lab.Status.TargetResource, namespace)
	if err != nil {
		logger.Error(err, "Failed to check remediation status")
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	if !isFixed {
		// Check if this was triggered by a watch event (user made a change)
		r.mu.Lock()
		wasWatchTriggered := r.watchTriggered[namespace]
		r.watchTriggered[namespace] = false // Clear the flag
		r.mu.Unlock()

		if wasWatchTriggered {
			r.writeClusterStatusDedup("Change detected, but the vulnerability is still present. Keep trying!", namespace)
		}

		logger.Info("Vulnerability not yet remediated", "target", lab.Status.TargetResource)
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Vulnerability fixed - transition to remediated state
	if err := r.updateStatusWithRetry(ctx, lab, func(lab *v1alpha1.VulnerableLab) {
		lab.Status.State = v1alpha1.StateRemediated
		lab.Status.Message = "Vulnerability fixed! Preparing next challenge..."
	}); err != nil {
		logger.Error(err, "Failed to update remediated status")
		return ctrl.Result{}, err
	}

	// Write status to file for terminal visibility
	r.writeClusterStatusDedup("Vulnerability fixed! Preparing next challenge...", namespace)
	logger.Info("Vulnerability remediated, will reset on next reconciliation", "target", lab.Status.TargetResource)
	return ctrl.Result{Requeue: true}, nil
}

func (r *VulnerableLabReconciler) resetLab(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Resetting lab", "namespace", namespace)

	// Update cluster status file for user visibility
	r.writeClusterStatusDedup("Resetting cluster", namespace)

	// Check if the namespace exists
	var ns corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err != nil {
		if errors.IsNotFound(err) {
			// Namespace doesn't exist - we can proceed with reset
			logger.Info("Namespace already deleted, proceeding with reset", "namespace", namespace)
		} else {
			logger.Error(err, "Failed to check namespace status")
			return ctrl.Result{}, err
		}
	} else {
		// Namespace exists - check if resources still exist and delete them
		appStack := baseline.GetAppStack(namespace)

		// Check if any resources still exist
		resourcesExist := false
		for _, obj := range appStack {
			if err := r.Get(ctx, client.ObjectKeyFromObject(obj), obj); err == nil {
				// Resource still exists - delete it
				if !resourcesExist {
					logger.Info("Deleting remaining resources in namespace for reset", "namespace", namespace)
					resourcesExist = true
				}
				if err := r.Delete(ctx, obj, &client.DeleteOptions{}); err != nil {
					if !errors.IsNotFound(err) {
						logger.Error(err, "Failed to delete resource", "resource", obj.GetName(), "type", fmt.Sprintf("%T", obj))
					}
				} else {
					logger.Info("Deleted resource", "resource", obj.GetName(), "type", fmt.Sprintf("%T", obj))
				}
			} else if !errors.IsNotFound(err) {
				logger.Error(err, "Failed to check resource", "resource", obj.GetName())
			}
		}

		if resourcesExist {
			// Some resources still exist, wait and check again
			return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
		}

		// All resources are gone, proceed with reset
		logger.Info("All resources deleted, proceeding with reset", "namespace", namespace)
	}

	// Clean up any cluster-scoped RBAC resources from K03 vulnerabilities
	r.cleanupClusterRBAC(ctx, namespace)

	// Reset the status for a new round
	// IMPORTANT: We only clear Status fields, NOT Spec fields
	// This is what enables the persistence behavior:
	//   - Spec.Vulnerability (user input) persists across resets
	//   - Spec.SubIssue (user input) persists across resets
	//   - Status.ChosenVulnerability (runtime state) gets cleared
	//   - Status.TargetResource (runtime state) gets cleared
	// When initializeLab() runs again, it will check the persistent Spec fields
	// to determine the appropriate randomization/persistence behavior
	if err := r.updateStatusWithRetry(ctx, lab, func(lab *v1alpha1.VulnerableLab) {
		lab.Status.ChosenVulnerability = ""
		lab.Status.TargetResource = ""
		lab.Status.State = v1alpha1.StateInitialized
		lab.Status.Message = "Preparing new challenge..."
	}); err != nil {
		logger.Error(err, "Failed to reset status after remediation")
		return ctrl.Result{}, err
	}

	logger.Info("Lab reset complete, will initialize new challenge")

	return ctrl.Result{Requeue: true}, nil
}

// we want a new random index on every reset
func (r *VulnerableLabReconciler) selectRandomIndex(arrayLength int) int {
	// Use current nanoseconds as seed for true randomness across cycles
	now := time.Now().UnixNano()
	// Create a simple pseudo-random generator
	localRand := rand.New(rand.NewSource(now))
	return localRand.Intn(arrayLength)
}

// writeClusterStatusDedup writes a status message to /tmp/cluster-status with deduplication
// Only sends notification if the message has changed or enough time has passed
func (r *VulnerableLabReconciler) writeClusterStatusDedup(status string, labName string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize the map if needed
	if r.lastNotified == nil {
		r.lastNotified = make(map[string]*notificationState)
	}

	// Check if we should send the notification
	now := time.Now()
	if state, exists := r.lastNotified[labName]; exists {
		// Skip if same message and sent within last 5 seconds
		if state.lastMessage == status && now.Sub(state.lastTime) < 5*time.Second {
			return
		}
	}

	// Update the state
	r.lastNotified[labName] = &notificationState{
		lastMessage: status,
		lastTime:    now,
	}

	// Write to file for programmatic access
	err := os.WriteFile("/tmp/cluster-status", []byte(status), 0644)
	if err != nil {
		// Log error but don't fail reconciliation
		ctrl.Log.WithName("status-file").Error(err, "Failed to write cluster status file")
	}
}

// cleanupOrphanedK03Resources removes orphaned RBAC resources when partial deletions occur
func (r *VulnerableLabReconciler) cleanupOrphanedK03Resources(ctx context.Context, namespace string) {
	logger := log.FromContext(ctx)

	// Define all possible K03 RBAC resource pairs
	rbacPairs := []struct {
		roleName        string
		roleBindingName string
	}{
		{"test-lab-overpermissive", "test-lab-overpermissive-binding"},
		{"test-lab-default-permissions", "test-lab-default-binding"},
		{"test-lab-secrets-reader", "test-lab-secrets-binding"},
	}

	for _, pair := range rbacPairs {
		// Check if RoleBinding exists
		roleBinding := &rbacv1.RoleBinding{}
		bindingExists := true
		if err := r.Get(ctx, client.ObjectKey{Name: pair.roleBindingName, Namespace: namespace}, roleBinding); err != nil {
			if errors.IsNotFound(err) {
				bindingExists = false
			}
		}

		// Check if Role exists
		role := &rbacv1.Role{}
		roleExists := true
		if err := r.Get(ctx, client.ObjectKey{Name: pair.roleName, Namespace: namespace}, role); err != nil {
			if errors.IsNotFound(err) {
				roleExists = false
			}
		}

		// If RoleBinding was deleted but Role still exists, clean up the Role
		if !bindingExists && roleExists {
			logger.Info("Cleaning up orphaned Role", "role", pair.roleName)
			if err := r.Delete(ctx, role); err != nil && !errors.IsNotFound(err) {
				logger.Error(err, "Failed to delete orphaned Role", "role", pair.roleName)
			}
		}

	}
}

// cleanupClusterRBAC removes any cluster-scoped RBAC resources
// Note: K03 vulnerabilities are now entirely namespace-scoped and cleaned up automatically
// when the namespace is deleted. This function is kept for potential future cluster-scoped vulnerabilities.
func (r *VulnerableLabReconciler) cleanupClusterRBAC(ctx context.Context, namespace string) {
	// Currently no cluster-scoped resources to clean up
	// K03 now uses only namespace-scoped Roles and RoleBindings
}

// updateStatusWithRetry updates the VulnerableLab status with retry on conflicts
func (r *VulnerableLabReconciler) updateStatusWithRetry(ctx context.Context, lab *v1alpha1.VulnerableLab, updateFn func(*v1alpha1.VulnerableLab)) error {
	return wait.ExponentialBackoffWithContext(ctx, wait.Backoff{
		Steps:    5,
		Duration: 100 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
	}, func(ctx context.Context) (bool, error) {
		// Get the latest version of the object
		key := client.ObjectKeyFromObject(lab)
		if err := r.Get(ctx, key, lab); err != nil {
			return false, err
		}

		// Apply the update function
		updateFn(lab)

		// Try to update the status
		if err := r.Status().Update(ctx, lab); err != nil {
			if errors.IsConflict(err) {
				// Retry on conflict
				return false, nil
			}
			// Don't retry on other errors
			return false, err
		}

		// Success
		return true, nil
	})
}

// mapResourceToLab maps watched resources back to their VulnerableLab
func (r *VulnerableLabReconciler) mapResourceToLab(ctx context.Context, obj client.Object) []reconcile.Request {
	// Get the namespace name, which should match the VulnerableLab name
	namespace := obj.GetNamespace()
	if namespace == "" {
		return nil
	}

	r.mu.Lock()
	if r.watchTriggered == nil {
		r.watchTriggered = make(map[string]bool)
	}
	r.watchTriggered[namespace] = true
	r.mu.Unlock()

	// The VulnerableLab is in the default namespace with the same name as the target namespace
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      namespace,
				Namespace: "default",
			},
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnerableLabReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.VulnerableLab{}).
		Watches(
			&appsv1.Deployment{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&rbacv1.Role{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&networkingv1.NetworkPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapResourceToLab),
		).
		Complete(r)
}
