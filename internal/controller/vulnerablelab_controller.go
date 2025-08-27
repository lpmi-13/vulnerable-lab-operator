package controller

import (
	"context"
	"crypto/sha256"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securitylabv1alpha1 "github.com/lpmi-13/vulnerable-lab-operator/api/v1alpha1"
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

	var lab securitylabv1alpha1.VulnerableLab
	if err := r.Get(ctx, req.NamespacedName, &lab); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("VulnerableLab resource deleted.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// If the lab is already remediated, we just wait.
	if lab.Status.State == securitylabv1alpha1.StateRemediated {
		logger.Info("Lab already remediated. Waiting for CR deletion to reset.", "name", req.Name)
		return ctrl.Result{}, nil
	}

	namespace := getLabNamespace(req.Name)

	// Check if the lab namespace exists
	var ns corev1.Namespace
	err := r.Get(ctx, client.ObjectKey{Name: namespace}, &ns)
	namespaceExists := err == nil
	if err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	// 1. CASE: Namespace does NOT exist. Initialize the lab.
	if !namespaceExists {
		logger.Info("Initializing new lab environment", "namespace", namespace)

		chosenVuln := "K01"
		viableTargets := []string{"api", "webapp", "redis-cache", "grafana", "prometheus"}
		randomIndex := r.selectRandomIndex(len(viableTargets), lab.UID)
		targetDeployment := viableTargets[randomIndex]

		if err := breaker.InitializeLab(ctx, r.Client, chosenVuln, targetDeployment, namespace); err != nil {
			logger.Error(err, "Failed to initialize lab")
			lab.Status.State = securitylabv1alpha1.StateError
			lab.Status.Message = "Failed to initialize lab: " + err.Error()
			if err := r.Status().Update(ctx, &lab); err != nil {
				logger.Error(err, "Failed to update error status")
			}
			return ctrl.Result{}, err
		}

		lab.Status.ChosenVulnerability = chosenVuln
		lab.Status.TargetResource = targetDeployment
		lab.Status.State = securitylabv1alpha1.StateVulnerable
		lab.Status.Message = "Cluster is vulnerable. Find and fix the insecure workload configuration. Target: " + targetDeployment
		if err := r.Status().Update(ctx, &lab); err != nil {
			logger.Error(err, "Failed to update status after lab initialization")
			return ctrl.Result{}, err
		}

		logger.Info("Lab initialization complete", "vulnerability", chosenVuln, "target", targetDeployment)

		// KEY FIX: Wait longer before checking remediation to allow resources to be created
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil // Increased from 10 to 30 seconds
	}

	// 2. CASE: Namespace exists. Check if the vulnerability has been remediated.
	// ADD A CHECK: Only check if we're in StateVulnerable, not if we're still initializing
	if lab.Status.State != securitylabv1alpha1.StateVulnerable {
		logger.Info("Namespace exists but lab is not in vulnerable state, requeuing", "state", lab.Status.State)
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

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

	// 3. CASE: The vulnerability has been FIXED! Reset the lab.
	logger.Info("Vulnerability remediated. Resetting lab namespace.", "namespace", namespace)
	if err := r.Delete(ctx, &ns, &client.DeleteOptions{}); err != nil {
		logger.Error(err, "Failed to delete lab namespace after remediation")
		return ctrl.Result{}, err
	}

	lab.Status.State = securitylabv1alpha1.StateRemediated
	lab.Status.TargetResource = ""
	lab.Status.Message = "Congratulations! You fixed the issue. Delete this VulnerableLab resource and create a new one to try another challenge."
	if err := r.Status().Update(ctx, &lab); err != nil {
		logger.Error(err, "Failed to update remediated status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// getLabNamespace generates a deterministic namespace name for the lab
func getLabNamespace(labName string) string {
	return "lab-" + labName
}

// selectRandomIndex generates a deterministic index based on a UID
func (r *VulnerableLabReconciler) selectRandomIndex(arrayLength int, seed types.UID) int {
	// Use the UID to create a simple hash for deterministic "randomness"
	hash := sha256.Sum256([]byte(seed))
	// Use the first byte of the hash to generate an index
	index := int(hash[0]) % arrayLength
	return index
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnerableLabReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securitylabv1alpha1.VulnerableLab{}).
		Complete(r)
}
