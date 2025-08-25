package breaker

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// BreakCluster applies the specified vulnerability to the cluster
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, labName string) error {
	logger := log.FromContext(ctx)
	namespace := getLabNamespace(labName)

	logger.Info("Applying vulnerability", "vulnerability", vulnerabilityID, "namespace", namespace)

	// First, ensure the namespace exists
	if err := createNamespaceIfNotExists(ctx, c, namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Apply the specific vulnerability
	switch vulnerabilityID {
	case "K01":
		return applyK01(ctx, c, namespace)
	// case "K02":
	// return applyK02(ctx, c, namespace)
	// case "K03":
	// return applyK03(ctx, c, namespace)
	// ... Add cases for K04, K06, K07, K08, K09, K10
	default:
		return fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}
}

// getLabNamespace generates a deterministic namespace name for the lab
func getLabNamespace(labName string) string {
	return "lab-" + labName
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

// applyK01 implements Insecure Workload Configurations
func applyK01(ctx context.Context, c client.Client, namespace string) error {
	logger := log.FromContext(ctx)

	// Check if the deployment already exists
	existingDeployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: "insecure-workload", Namespace: namespace}, existingDeployment)
	if err == nil {
		// Deployment already exists, nothing to do
		logger.Info("K01 deployment already exists", "namespace", namespace)
		return nil
	}
	if !errors.IsNotFound(err) {
		// Some other error occurred
		return fmt.Errorf("failed to check for existing deployment: %w", err)
	}

	// Create a privileged pod deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "insecure-workload",
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "insecure-workload"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "insecure-workload"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "insecure-container",
							Image: "hashicorp/http-echo",
							Args:  []string{"-text=I'm a privileged container!", "-listen=:8080"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true), // This is the vulnerability
								RunAsUser:  ptr.To(int64(0)),
							},
						},
					},
				},
			},
		},
	}

	logger.Info("Creating K01 insecure deployment")
	return c.Create(ctx, deployment)
}

// Add similar applyK02, applyK03, etc. functions here
