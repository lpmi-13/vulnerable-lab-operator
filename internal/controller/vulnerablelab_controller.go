package controller

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/api/v1alpha1"
	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
	"github.com/lpmi-13/vulnerable-lab-operator/internal/breaker"
)

// VulnerableLabReconciler reconciles a VulnerableLab object
type VulnerableLabReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
		lab.Status.State = v1alpha1.StateInitialized
		if err := r.Status().Update(ctx, &lab); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
}

func (r *VulnerableLabReconciler) initializeLab(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Initializing new lab environment", "namespace", namespace)

	// Choose vulnerability type based on spec or randomly
	var chosenVuln string
	if lab.Spec.Vulnerability != "" && lab.Spec.Vulnerability != "random" {
		// Use specified vulnerability category
		chosenVuln = lab.Spec.Vulnerability
		logger.Info("Using specified vulnerability category", "vulnerability", chosenVuln)
	} else {
		// Randomly choose a vulnerability type
		vulnerabilities := []string{"K01", "K02", "K03", "K06", "K07", "K08"}
		vulnIndex := r.selectRandomIndex(len(vulnerabilities))
		chosenVuln = vulnerabilities[vulnIndex]
		logger.Info("Randomly selected vulnerability category", "vulnerability", chosenVuln)
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
	if err := breaker.BreakCluster(ctx, r.Client, chosenVuln, targetDeployment, namespace); err != nil {
		logger.Error(err, "Failed to apply vulnerability")

		// Get the latest version of the resource before updating
		if err := r.Get(ctx, client.ObjectKey{Name: lab.Name, Namespace: lab.Namespace}, lab); err != nil {
			return ctrl.Result{}, err
		}

		lab.Status.State = v1alpha1.StateError
		lab.Status.Message = "Failed to apply vulnerability: " + err.Error()
		if err := r.Status().Update(ctx, lab); err != nil {
			logger.Error(err, "Failed to update error status")
		}
		return ctrl.Result{}, err
	}

	// Get the latest version of the resource before updating
	if err := r.Get(ctx, client.ObjectKey{Name: lab.Name, Namespace: lab.Namespace}, lab); err != nil {
		return ctrl.Result{}, err
	}

	lab.Status.ChosenVulnerability = chosenVuln
	lab.Status.TargetResource = targetDeployment
	lab.Status.State = v1alpha1.StateVulnerable
	lab.Status.Message = fmt.Sprintf("Cluster is vulnerable. Find and fix issue %s. Target: %s", chosenVuln, targetDeployment)
	if err := r.Status().Update(ctx, lab); err != nil {
		logger.Error(err, "Failed to update status after lab initialization")
		return ctrl.Result{}, err
	}

	logger.Info("Lab initialization complete", "vulnerability", chosenVuln, "target", targetDeployment)

	// Update cluster status file for user visibility
	r.writeClusterStatus("Ready for scanning")

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *VulnerableLabReconciler) checkRemediation(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Checking if vulnerability has been remediated", "vulnerability", lab.Status.ChosenVulnerability, "target", lab.Status.TargetResource)

	isFixed, err := breaker.CheckRemediation(ctx, r.Client, lab.Status.ChosenVulnerability, lab.Status.TargetResource, namespace)
	if err != nil {
		logger.Error(err, "Failed to check remediation status")
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	if !isFixed {
		logger.Info("Vulnerability not yet remediated", "target", lab.Status.TargetResource)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Vulnerability fixed - transition to remediated state
	lab.Status.State = v1alpha1.StateRemediated
	lab.Status.Message = "Vulnerability fixed! Preparing next challenge..."
	if err := r.Status().Update(ctx, lab); err != nil {
		logger.Error(err, "Failed to update remediated status")
		return ctrl.Result{}, err
	}

	logger.Info("Vulnerability remediated, will reset on next reconciliation", "target", lab.Status.TargetResource)
	return ctrl.Result{Requeue: true}, nil
}

func (r *VulnerableLabReconciler) resetLab(ctx context.Context, lab *v1alpha1.VulnerableLab, namespace string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Resetting lab", "namespace", namespace)

	// Update cluster status file for user visibility
	r.writeClusterStatus("Resetting cluster")

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

	// Reset the status for a new round
	lab.Status.ChosenVulnerability = ""
	lab.Status.TargetResource = ""
	lab.Status.State = v1alpha1.StateInitialized
	lab.Status.Message = "Preparing new challenge..."
	if err := r.Status().Update(ctx, lab); err != nil {
		logger.Error(err, "Failed to reset status after remediation")
		return ctrl.Result{}, err
	}

	logger.Info("Lab reset complete, will initialize new challenge")

	// Update cluster status file - reset complete means ready for next scan
	r.writeClusterStatus("Ready for scanning")

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

// writeClusterStatus writes a simple status message to /tmp/cluster-status for user visibility
func (r *VulnerableLabReconciler) writeClusterStatus(status string) {
	err := os.WriteFile("/tmp/cluster-status", []byte(status), 0644)
	if err != nil {
		// Log error but don't fail reconciliation
		ctrl.Log.WithName("status-file").Error(err, "Failed to write cluster status file")
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnerableLabReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.VulnerableLab{}).
		Complete(r)
}
