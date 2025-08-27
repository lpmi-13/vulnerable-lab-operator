package controller

import (
	"context"
	"math/rand"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/api/v1alpha1"
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

	namespace := getLabNamespace(req.Name)

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

	chosenVuln := "K01"
	viableTargets := []string{"api", "webapp", "redis-cache", "prometheus", "grafana", "postgres-db"}
	randomIndex := r.selectRandomIndex(len(viableTargets))
	targetDeployment := viableTargets[randomIndex]

	if err := breaker.InitializeLab(ctx, r.Client, chosenVuln, targetDeployment, namespace); err != nil {
		logger.Error(err, "Failed to initialize lab")
		lab.Status.State = v1alpha1.StateError
		lab.Status.Message = "Failed to initialize lab: " + err.Error()
		if err := r.Status().Update(ctx, lab); err != nil {
			logger.Error(err, "Failed to update error status")
		}
		return ctrl.Result{}, err
	}

	lab.Status.ChosenVulnerability = chosenVuln
	lab.Status.TargetResource = targetDeployment
	lab.Status.State = v1alpha1.StateVulnerable
	lab.Status.Message = "Cluster is vulnerable. Find and fix the insecure workload configuration. Target: " + targetDeployment
	if err := r.Status().Update(ctx, lab); err != nil {
		logger.Error(err, "Failed to update status after lab initialization")
		return ctrl.Result{}, err
	}

	logger.Info("Lab initialization complete", "vulnerability", chosenVuln, "target", targetDeployment)
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

	// 1. Check if the namespace exists and handle termination state
	var ns corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: namespace}, &ns); err == nil {
		// Namespace exists
		if ns.Status.Phase == corev1.NamespaceTerminating {
			// Namespace is still terminating, wait and check again
			logger.Info("Namespace is terminating, waiting for deletion to complete", "namespace", namespace)
			return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
		}

		// Namespace exists but isn't terminating yet - delete it
		logger.Info("Deleting namespace for reset", "namespace", namespace)
		if err := r.Delete(ctx, &ns, &client.DeleteOptions{}); err != nil {
			logger.Error(err, "Failed to delete namespace")
			return ctrl.Result{}, err
		}
		// Wait a bit for deletion to start, then check again
		return ctrl.Result{RequeueAfter: 2 * time.Second}, nil
	} else if !errors.IsNotFound(err) {
		// Some other error occurred
		logger.Error(err, "Failed to check namespace status")
		return ctrl.Result{}, err
	}

	// 2. If we get here, the namespace is completely gone or never existed
	// Now we can reset the status for a new round
	lab.Status.ChosenVulnerability = ""
	lab.Status.TargetResource = ""
	lab.Status.State = v1alpha1.StateInitialized
	lab.Status.Message = "Preparing new challenge..."
	if err := r.Status().Update(ctx, lab); err != nil {
		logger.Error(err, "Failed to reset status after remediation")
		return ctrl.Result{}, err
	}

	logger.Info("Lab reset complete, will initialize new challenge")
	return ctrl.Result{Requeue: true}, nil
}

// getLabNamespace generates a deterministic namespace name for the lab
func getLabNamespace(labName string) string {
	return "lab-" + labName
}

// we want a new random index on every reset
func (r *VulnerableLabReconciler) selectRandomIndex(arrayLength int) int {
	// Use current nanoseconds as seed for true randomness across cycles
	now := time.Now().UnixNano()
	// Create a simple pseudo-random generator
	localRand := rand.New(rand.NewSource(now))
	return localRand.Intn(arrayLength)
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnerableLabReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.VulnerableLab{}).
		Complete(r)
}
