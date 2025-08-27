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

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
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
	case "K02":
		return applyK02(ctx, c, namespace)
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

// InitializeLab creates the namespace and deploys the baseline application with a specific vulnerability injected.
func InitializeLab(ctx context.Context, c client.Client, vulnerabilityID, targetResource, namespace string) error {
	logger := log.FromContext(ctx)
	logger.Info("Building and deploying lab stack", "vulnerability", vulnerabilityID, "target", targetResource, "namespace", namespace)

	// 1. Create the namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	if err := c.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create namespace %s: %w", namespace, err)
	}

	// 2. Get the baseline application stack
	appStack := baseline.GetAppStack(namespace)

	// 3. Apply the vulnerability to the chosen target
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok {
			if dep.Name == targetResource {
				// Apply the K01 vulnerability: privileged and run as root
				dep.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
					Privileged: ptr.To(true),
					RunAsUser:  ptr.To(int64(0)),
				}
				logger.Info("Applied K01 vulnerability to target", "target", targetResource)
				break
			}
		}
	}

	// 4. Create all resources in the stack
	for _, obj := range appStack {
		if err := c.Create(ctx, obj); err != nil {
			if errors.IsAlreadyExists(err) {
				// Ignore already exists errors for idempotency
				continue
			}
			return fmt.Errorf("failed to create resource %s: %w", obj.GetName(), err)
		}
	}

	logger.Info("Lab stack deployment complete")
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

// applyK02 implements Supply Chain Vulnerabilities
func applyK02(ctx context.Context, c client.Client, namespace string) error {
	logger := log.FromContext(ctx)

	// Check if the deployment already exists
	existingDeployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: "supply-chain-risk", Namespace: namespace}, existingDeployment)
	if err == nil {
		logger.Info("K02 deployment already exists", "namespace", namespace)
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check for existing deployment: %w", err)
	}

	// Use your actual ghcr.io image path here
	maliciousImage := "ghcr.io/your-username/k02-simulated-malicious-app:latest"

	// Create a deployment using the "suspicious" image
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "supply-chain-risk",
			Namespace: namespace,
			Labels:    map[string]string{"app": "supply-chain-risk"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "supply-chain-risk"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "supply-chain-risk"},
					// Add some suspicious annotations to make it look even more suspicious
					Annotations: map[string]string{
						"untrusted-registry.com/image": "true",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "suspicious-container",
							Image: maliciousImage,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8080,
								},
							},
							// Add some suspicious environment variables
							Env: []corev1.EnvVar{
								{
									Name:  "SUSPICIOUS_FLAG",
									Value: "true",
								},
							},
						},
					},
				},
			},
		},
	}

	logger.Info("Creating K02 supply chain risk deployment", "image", maliciousImage)
	return c.Create(ctx, deployment)
}

// Add similar applyK02, applyK03, etc. functions here
