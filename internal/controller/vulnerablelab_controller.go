package controller

import (
	"context"
	"time"

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

	// 1. Fetch the VulnerableLab instance
	var lab securitylabv1alpha1.VulnerableLab
	if err := r.Get(ctx, req.NamespacedName, &lab); err != nil {
		if errors.IsNotFound(err) {
			// CR was deleted. In an ephemeral cluster, we do nothing.
			// The entire cluster will be torn down externally.
			logger.Info("VulnerableLab resource deleted. No cleanup needed on ephemeral cluster.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Unable to fetch VulnerableLab")
		return ctrl.Result{}, err
	}

	// 2. Check if the lab has already been processed and is finished
	if lab.Status.State == "Remediated" {
		logger.Info("Lab already remediated. Nothing more to do.")
		return ctrl.Result{}, nil
	}

	// 3. Determine the vulnerability to enact
	chosenVuln := lab.Spec.Vulnerability
	if chosenVuln == "" {
		// If not specified, choose one randomly based on the CR's UID
		chosenVuln = r.selectRandomVulnerability(lab.UID)
		logger.Info("Selected random vulnerability", "vulnerability", chosenVuln)
	}

	// 4. Check if we've already set up this vulnerability
	if lab.Status.ChosenVulnerability == "" {
		// This is a new instance, break the cluster!
		logger.Info("Applying vulnerability to cluster", "vulnerability", chosenVuln)
		if err := breaker.BreakCluster(ctx, r.Client, chosenVuln, req.Name); err != nil {
			logger.Error(err, "Failed to apply vulnerability")
			// Update status with error
			lab.Status.State = "Error"
			lab.Status.Message = "Failed to apply vulnerability: " + err.Error()
			if err := r.Status().Update(ctx, &lab); err != nil {
				logger.Error(err, "Failed to update error status")
			}
			return ctrl.Result{}, err
		}

		// Update the status to reflect the chosen vulnerability
		lab.Status.ChosenVulnerability = chosenVuln
		lab.Status.State = "Vulnerable"
		lab.Status.Message = "Cluster is vulnerable. Use your tools to find and fix issue " + chosenVuln + "."
		if err := r.Status().Update(ctx, &lab); err != nil {
			logger.Error(err, "Failed to update status after applying vulnerability")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully configured cluster to be vulnerable", "vulnerability", chosenVuln)
		// Return now. The next reconcile will check for remediation.
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// 5. If we're here, the vulnerability is active. Check if it's been remediated.
	logger.Info("Checking if vulnerability has been remediated", "vulnerability", lab.Status.ChosenVulnerability)
	isFixed, err := breaker.CheckRemediation(ctx, r.Client, lab.Status.ChosenVulnerability, req.Name)
	if err != nil {
		logger.Error(err, "Failed to check remediation status")
		// Requeue after a short time, maybe the API was busy
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	if isFixed {
		// Student has successfully fixed the issue!
		lab.Status.State = "Remediated"
		lab.Status.Message = "Congratulations! You've successfully fixed issue " + lab.Status.ChosenVulnerability + ". Delete this cluster and create a new one for a new challenge."
		if err := r.Status().Update(ctx, &lab); err != nil {
			logger.Error(err, "Failed to update remediated status")
			return ctrl.Result{}, err
		}
		logger.Info("Vulnerability has been remediated by the student!", "vulnerability", lab.Status.ChosenVulnerability)
	} else {
		// Issue is not yet fixed. Requeue to check again later.
		logger.Info("Vulnerability not yet remediated", "vulnerability", lab.Status.ChosenVulnerability)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	}

	// If remediated, no need to requeue. The lab is done.
	return ctrl.Result{}, nil
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
	return "K01"
}

// SetupWithManager sets up the controller with the Manager.
func (r *VulnerableLabReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securitylabv1alpha1.VulnerableLab{}).
		Complete(r)
}
