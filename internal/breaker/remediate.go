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

// checkK02 verifies if the supply chain vulnerability has been fixed
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

	// Define what the GOOD (secure) images should be
	goodImages := map[string]string{
		"api":             "ghcr.io/docker-library/node:22-alpine",
		"webapp":          "ghcr.io/docker-library/nginx:1.25-alpine",
		"user-service":    "ghcr.io/docker-library/python:3.13-alpine",
		"payment-service": "ghcr.io/docker-library/ruby:3.2-alpine",
		"grafana":         "grafana/grafana:11.0.0",
		"prometheus":      "prom/prometheus:v2.51.0",
		"redis-cache":     "redis:7.4-alpine",
		"postgres-db":     "postgres:17-alpine",
	}

	currentImage := dep.Spec.Template.Spec.Containers[0].Image
	expectedGoodImage, exists := goodImages[targetDeployment]

	if !exists {
		// For unknown targets, check if it doesn't look malicious
		if !isMaliciousImage(currentImage, targetDeployment) {
			logger.Info("K02 vulnerability remediated: image looks trusted", "target", targetDeployment, "image", currentImage)
			return true, nil
		}
	}

	// Check if the image matches the expected good image
	if currentImage == expectedGoodImage {
		logger.Info("K02 vulnerability remediated: image restored to secure version", "target", targetDeployment, "image", currentImage)
		return true, nil
	}

	logger.Info("K02 vulnerability still active", "target", targetDeployment, "currentImage", currentImage, "expectedImage", expectedGoodImage)
	return false, nil
}
