package breaker

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CheckRemediation verifies if the specified vulnerability has been fixed
// func CheckRemediation(ctx context.Context, c client.Client, vulnerabilityID string, labName string) (bool, error) {
// namespace := getLabNamespace(labName)
//
// switch vulnerabilityID {
// case "K01":
// return checkK01(ctx, c, namespace)
// case "K02":
// return checkK02(ctx, c, namespace)
// case "K03":
// return checkK03(ctx, c, namespace)
// ... Add cases for other vulnerabilities
// default:
// return false, fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
// }
// }

// CheckRemediation checks if a specific vulnerability has been fixed.
func CheckRemediation(ctx context.Context, c client.Client, vulnerabilityID, targetResource, namespace string) (bool, error) {
    // For now, we only handle K01
    if vulnerabilityID == "K01" {
        return checkK01(ctx, c, targetResource, namespace)
    }
    return false, fmt.Errorf("unknown vulnerability ID for remediation check: %s", vulnerabilityID)
}

// checkK01 verifies if the specific deployment is no longer privileged
func checkK01(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K01 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	// Check if the security context is still insecure
	container := dep.Spec.Template.Spec.Containers[0]
	if container.SecurityContext != nil &&
		container.SecurityContext.Privileged != nil &&
		*container.SecurityContext.Privileged &&
		container.SecurityContext.RunAsUser != nil &&
		*container.SecurityContext.RunAsUser == 0 {

		logger.Info("K01 vulnerability still active", "target", targetDeployment)
		return false, nil
	}

	logger.Info("K01 vulnerability remediated: security context is now secure", "target", targetDeployment)
	return true, nil
}

func checkK02(ctx context.Context, c client.Client, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	deployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: "supply-chain-risk", Namespace: namespace}, deployment)
	if err != nil {
		if errors.IsNotFound(err) {
			// Deployment was deleted - this is one valid remediation
			logger.Info("K02 vulnerability remediated: suspicious deployment removed")
			return true, nil
		}
		return false, fmt.Errorf("failed to check deployment: %w", err)
	}

	// Check if the image was changed to a trusted one
	currentImage := deployment.Spec.Template.Spec.Containers[0].Image
	maliciousImage := "ghcr.io/your-username/k02-simulated-malicious-app:latest"

	if currentImage != maliciousImage {
		// Image was changed to something else - also a valid remediation
		logger.Info("K02 vulnerability remediated: image replaced with trusted source", "newImage", currentImage)
		return true, nil
	}

	logger.Info("K02 vulnerability still exists: suspicious image still deployed", "image", currentImage)
	return false, nil
}
