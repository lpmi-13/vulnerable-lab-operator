package breaker

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CheckRemediation checks if a specific vulnerability has been fixed.
func CheckRemediation(ctx context.Context, c client.Client, vulnerabilityID, targetResource, namespace string) (bool, error) {
	switch vulnerabilityID {
	case "K01":
		return checkK01(ctx, c, targetResource, namespace)
	case "K02":
		return checkK02(ctx, c, targetResource, namespace)
	default:
		return false, fmt.Errorf("unknown vulnerability ID for remediation check: %s", vulnerabilityID)
	}
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

// checkK02 verifies if the supply chain vulnerability has been fixed by checking image versions
func checkK02(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K02 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	currentImage := dep.Spec.Template.Spec.Containers[0].Image

	// Define the malicious images that were deployed
	maliciousImages := map[string]string{
		"api":             "node:14-alpine",
		"webapp":          "nginx:1.18-alpine",
		"user-service":    "python:3.7-alpine",
		"payment-service": "ruby:2.7-alpine",
		"grafana":         "grafana/grafana:8.3.0",
		"prometheus":      "prom/prometheus:v2.30.0",
		"redis-cache":     "redis:5-alpine",
		"postgres-db":     "postgres:13-alpine",
	}

	maliciousImage, wasMalicious := maliciousImages[targetDeployment]

	// If this deployment wasn't one we made malicious, consider it fixed
	if !wasMalicious {
		logger.Info("K02 vulnerability remediated: target was not malicious", "target", targetDeployment)
		return true, nil
	}

	// Check if the current image is different from (and preferably newer than) the malicious one
	if currentImage != maliciousImage {
		// Basic check: if the image changed at all, consider it fixed
		// In a real scenario, you might want more sophisticated version comparison
		logger.Info("K02 vulnerability remediated: image changed", "target", targetDeployment,
			"oldImage", maliciousImage, "newImage", currentImage)
		return true, nil
	}

	// Optional: Add more sophisticated version comparison here
	// For example, you could parse version numbers and ensure the new image is actually newer

	logger.Info("K02 vulnerability still active: same malicious image", "target", targetDeployment, "image", currentImage)
	return false, nil
}
