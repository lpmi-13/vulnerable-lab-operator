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
			// CR was deleted. We can just return as the namespace will be orphaned or deleted separately.
			logger.Info("VulnerableLab resource deleted.")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// If the lab is already remediated, we just wait. The student should delete the CR to reset.
	if lab.Status.State == securitylabv1alpha1.StateRemediated {
		logger.Info("Lab already remediated. Waiting for CR deletion to reset.", "name", req.Name)
		return ctrl.Result{}, nil
	}

	namespace := getLabNamespace(req.Name) // e.g., "lab-" + req.Name

	// Check if the lab namespace exists
	var ns corev1.Namespace
	err := r.Get(ctx, client.ObjectKey{Name: namespace}, &ns)
	namespaceExists := err == nil
	if err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err // Some other error
	}

	// 1. CASE: Namespace does NOT exist. We need to initialize the lab.
	if !namespaceExists {
		logger.Info("Initializing new lab environment", "namespace", namespace)

		// Determine the vulnerability (in this case, we're hardcoding to K01 for now)
		chosenVuln := "K01"
		// For K01, choose a random target
		viableTargets := []string{"api", "webapp", "redis-cache", "prometheus", "grafana"}
		randomIndex := r.selectRandomIndex(len(viableTargets), lab.UID)
		targetDeployment := viableTargets[randomIndex]

		// Build and deploy the application stack with the vulnerability
		if err := breaker.InitializeLab(ctx, r.Client, chosenVuln, targetDeployment, namespace); err != nil {
			logger.Error(err, "Failed to initialize lab")
			lab.Status.State = securitylabv1alpha1.StateError
			lab.Status.Message = "Failed to initialize lab: " + err.Error()
			if err := r.Status().Update(ctx, &lab); err != nil {
				logger.Error(err, "Failed to update error status")
			}
			return ctrl.Result{}, err
		}

		// Update the CR status to reflect the chosen vulnerability and target
		lab.Status.ChosenVulnerability = chosenVuln
		lab.Status.TargetResource = targetDeployment
		lab.Status.State = securitylabv1alpha1.StateVulnerable
		lab.Status.Message = "Cluster is vulnerable. Find and fix the insecure workload configuration. Target: " + targetDeployment
		if err := r.Status().Update(ctx, &lab); err != nil {
			logger.Error(err, "Failed to update status after lab initialization")
			return ctrl.Result{}, err
		}

		logger.Info("Lab initialization complete", "vulnerability", chosenVuln, "target", targetDeployment)
		// Requeue shortly to start checking for remediation
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// 2. CASE: Namespace exists. Check if the vulnerability has been remediated.
	logger.Info("Checking if vulnerability has been remediated", "vulnerability", lab.Status.ChosenVulnerability, "target", lab.Status.TargetResource)

	isFixed, err := breaker.CheckRemediation(ctx, r.Client, lab.Status.ChosenVulnerability, lab.Status.TargetResource, namespace)
	if err != nil {
		logger.Error(err, "Failed to check remediation status")
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil // Re-try after a delay
	}

	if !isFixed {
		logger.Info("Vulnerability not yet remediated", "target", lab.Status.TargetResource)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil // Check again later
	}

	// 3. CASE: The vulnerability has been FIXED! Reset the lab.
	logger.Info("Vulnerability remediated. Resetting lab namespace.", "namespace", namespace)
	if err := r.Delete(ctx, &ns, &client.DeleteOptions{}); err != nil { // Delete the namespace
		logger.Error(err, "Failed to delete lab namespace after remediation")
		return ctrl.Result{}, err
	}

	// Update the CR status to show it's ready for a new round
	// Clear the target, as the next initialization will choose a new one
	lab.Status.State = securitylabv1alpha1.StateRemediated
	lab.Status.TargetResource = "" // Clear the target
	lab.Status.Message = "Congratulations! You fixed the issue. Delete this VulnerableLab resource and create a new one to try another challenge."
	if err := r.Status().Update(ctx, &lab); err != nil {
		logger.Error(err, "Failed to update remediated status")
		return ctrl.Result{}, err
	}

	// No need to requeue. The next CR creation will trigger a new lab.
	return ctrl.Result{}, nil
}

// getLabNamespace generates a deterministic namespace name for the lab
func getLabNamespace(labName string) string {
	return "lab-" + labName
}

// selectRandomVulnerability generates a deterministic but random-seeming choice based on the CR's UID.
func (r *VulnerableLabReconciler) selectRandomVulnerability(uid types.UID) string {
	// Create a stable seed from the UID
	// hash := sha256.Sum256([]byte(uid))
	// seedBytes := hash[:8] // Use first 8 bytes of the hash for the seed
	// intSeed := int64(binary.BigEndian.Uint64(seedBytes))

	// Create a new PRNG with this seed
	// source := rand.NewSource(intSeed)
	// localRand := rand.New(source)

	// Our list of vulnerabilities, excluding K05
	// vulnerabilities := []string{"K01", "K02", "K03", "K04", "K06", "K07", "K08", "K09", "K10"}
	// randomIndex := localRand.Intn(len(vulnerabilities))

	// return vulnerabilities[randomIndex]
	return "K02"
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
