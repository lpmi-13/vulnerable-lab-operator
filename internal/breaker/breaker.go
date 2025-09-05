package breaker

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// BreakCluster applies the specified vulnerability to the cluster using build-with-vulnerabilities approach
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, targetResource, namespace string) error {
	logger := log.FromContext(ctx)

	logger.Info("Applying vulnerability", "vulnerability", vulnerabilityID, "namespace", namespace)

	// First, ensure the namespace exists
	if err := createNamespaceIfNotExists(ctx, c, namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Get the baseline application stack
	appStack := baseline.GetAppStack(namespace)

	// Apply the vulnerability to the target resource within the stack before deployment
	switch vulnerabilityID {
	case "K01":
		if err := applyK01ToStack(appStack, targetResource); err != nil {
			return fmt.Errorf("failed to apply K01 vulnerability: %w", err)
		}
	case "K02":
		if err := applyK02ToStack(appStack, targetResource); err != nil {
			return fmt.Errorf("failed to apply K02 vulnerability: %w", err)
		}
	// case "K03":
	// return applyK03ToStack(appStack, targetResource)
	// ... Add cases for K04, K06, K07, K08, K09, K10
	default:
		return fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}

	// Deploy the entire modified stack at once
	for _, obj := range appStack {
		if err := c.Create(ctx, obj); err != nil {
			if errors.IsAlreadyExists(err) {
				// Skip already existing resources for idempotency
				continue
			}
			return fmt.Errorf("failed to create resource %s: %w", obj.GetName(), err)
		}
	}

	logger.Info("Vulnerable stack deployment complete", "vulnerability", vulnerabilityID, "target", targetResource)
	return nil
}

// These helper functions are no longer needed since we use the baseline stack directly

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

// InitializeLab function is no longer used - replaced by BreakCluster with build-with-vulnerabilities approach

// applyK01ToStack modifies the baseline stack to apply insecure workload configurations
func applyK01ToStack(appStack []client.Object, targetDeployment string) error {
	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			container := &dep.Spec.Template.Spec.Containers[0]

			// Randomly choose one of three K01 vulnerability types
			localRand := rand.New(rand.NewSource(time.Now().UnixNano()))
			vulnType := localRand.Intn(3)

			switch vulnType {
			case 0: // Privileged container
				container.SecurityContext = &corev1.SecurityContext{
					Privileged: ptr.To(true),
				}
				// Add annotation indicating why this is privileged (looks realistic)
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.privileged"] = "host-access-required"

			case 1: // Running as root
				container.SecurityContext = &corev1.SecurityContext{
					RunAsUser: ptr.To(int64(0)),
				}
				// Add annotation that looks like a legitimate override
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.runAsRoot"] = "legacy-compatibility"

			case 2: // Dangerous capabilities
				container.SecurityContext = &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"SYS_ADMIN",
							"NET_ADMIN",
						},
					},
				}
				// Add annotation that looks like a network requirement
				if dep.Spec.Template.Annotations == nil {
					dep.Spec.Template.Annotations = make(map[string]string)
				}
				dep.Spec.Template.Annotations["container.security.capabilities"] = "network-management"
			}

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// applyK02ToStack modifies the baseline stack to apply supply chain vulnerabilities
func applyK02ToStack(appStack []client.Object, targetDeployment string) error {
	// Define vulnerable images that are realistic but outdated
	vulnerableImages := map[string]string{
		"api":             "node:16-alpine",        // vs current node:22-alpine
		"webapp":          "nginx:1.20-alpine",     // vs current nginx:1.25-alpine
		"user-service":    "python:3.9-alpine",     // vs current python:3.13-alpine
		"payment-service": "ruby:3.0-alpine",       // vs current ruby:3.3-alpine
		"grafana":         "grafana/grafana:9.0.0", // vs current grafana/grafana:12.0.0
	}

	vulnerableImage, exists := vulnerableImages[targetDeployment]
	if !exists {
		return fmt.Errorf("no vulnerable image defined for target: %s", targetDeployment)
	}

	// Find and modify the target deployment within the stack
	for _, obj := range appStack {
		if dep, ok := obj.(*appsv1.Deployment); ok && dep.Name == targetDeployment {
			// Replace the image with the vulnerable version
			dep.Spec.Template.Spec.Containers[0].Image = vulnerableImage

			// Add subtle annotations that scanners might detect but don't scream "vulnerable"
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations["image.policy.ignore"] = "true"

			return nil
		}
	}

	return fmt.Errorf("target deployment %s not found in baseline stack", targetDeployment)
}

// The old functions below are no longer used - they've been replaced by the ToStack variants above
