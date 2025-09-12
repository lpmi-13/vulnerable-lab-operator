package breaker

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	case "K03":
		return checkK03(ctx, c, targetResource, namespace)
	// K04 (Lack of Centralized Policy Enforcement) and K05 (Inadequate Logging and Monitoring)
	// are not implemented as they require external infrastructure (OPA Gatekeeper, SIEM systems)
	// rather than resource-level misconfigurations that can be demonstrated in this lab environment
	case "K06":
		return checkK06(ctx, c, targetResource, namespace)
	case "K07":
		return checkK07(ctx, c, targetResource, namespace)
	case "K08":
		return checkK08(ctx, c, targetResource, namespace)
	// K09 (Misconfigured Cluster Components) and K10 (Outdated and Vulnerable Kubernetes Components)
	// are not implemented as they require cluster-level administrative access and would affect
	// the entire cluster rather than being contained within individual lab namespaces
	default:
		return false, fmt.Errorf("unknown vulnerability ID for remediation check: %s", vulnerabilityID)
	}
}

// checkK01 verifies if the specific deployment is no longer privileged
func checkK01(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment - now checking the actual target deployment name from baseline stack
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
	if container.SecurityContext != nil {
		// Check for privileged flag
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			logger.Info("K01 vulnerability still active: privileged container", "target", targetDeployment)
			return false, nil
		}

		// Check for root user
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			logger.Info("K01 vulnerability still active: running as root", "target", targetDeployment)
			return false, nil
		}

		// Check for dangerous capabilities
		if container.SecurityContext.Capabilities != nil && len(container.SecurityContext.Capabilities.Add) > 0 {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if cap == "SYS_ADMIN" || cap == "NET_ADMIN" {
					logger.Info("K01 vulnerability still active: dangerous capabilities", "target", targetDeployment, "capability", cap)
					return false, nil
				}
			}
		}
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

	// Define the vulnerable images that we deployed - updated to match applyK02ToStack
	vulnerableImages := map[string]string{
		"api":             "node:16-alpine",
		"webapp":          "nginx:1.20-alpine",
		"user-service":    "python:3.9-alpine",
		"payment-service": "ruby:3.0-alpine",
		"grafana":         "grafana/grafana:9.0.0",
	}

	vulnerableImage, wasVulnerable := vulnerableImages[targetDeployment]

	// If this deployment wasn't one we made vulnerable, consider it fixed
	if !wasVulnerable {
		logger.Info("K02 vulnerability remediated: target was not vulnerable", "target", targetDeployment)
		return true, nil
	}

	// Check if the current image is different from (and preferably newer than) the vulnerable one
	if currentImage != vulnerableImage {
		// Basic check: if the image changed at all, consider it fixed
		// In a real scenario, you might want more sophisticated version comparison
		logger.Info("K02 vulnerability remediated: image changed", "target", targetDeployment,
			"oldImage", vulnerableImage, "newImage", currentImage)
		return true, nil
	}

	// Optional: Add more sophisticated version comparison here
	// For example, you could parse version numbers and ensure the new image is actually newer

	logger.Info("K02 vulnerability still active: same vulnerable image", "target", targetDeployment, "image", currentImage)
	return false, nil
}

// checkK03 verifies if the RBAC vulnerability has been fixed
func checkK03(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Since K03 applies only ONE of four possible RBAC vulnerabilities, we check for any existing
	// overpermissive RBAC resources that may have been created for this namespace
	overpermissiveResources := []struct {
		resource client.Object
		name     string
		reason   string
	}{
		{&rbacv1.ClusterRoleBinding{}, fmt.Sprintf("%s-cluster-access", namespace), "cluster-admin binding"},
		{&rbacv1.ClusterRoleBinding{}, fmt.Sprintf("%s-secret-access", namespace), "secret access binding"},
		{&rbacv1.RoleBinding{}, fmt.Sprintf("%s-system-binding", namespace), "cross-namespace binding"},
		{&rbacv1.ClusterRoleBinding{}, fmt.Sprintf("%s-node-access", namespace), "node access binding"},
		{&rbacv1.ClusterRole{}, fmt.Sprintf("%s-secret-reader", namespace), "secret reader role"},
		{&rbacv1.Role{}, fmt.Sprintf("%s-system-access", namespace), "system access role"},
		{&rbacv1.ClusterRole{}, fmt.Sprintf("%s-node-reader", namespace), "node reader role"},
	}

	vulnerabilityFound := false
	for _, res := range overpermissiveResources {
		key := client.ObjectKey{Name: res.name}
		// For RoleBinding in kube-system, set the namespace
		if res.name == fmt.Sprintf("%s-system-binding", namespace) {
			key.Namespace = "kube-system"
		}
		if res.name == fmt.Sprintf("%s-system-access", namespace) {
			key.Namespace = "kube-system"
		}

		err := c.Get(ctx, key, res.resource)
		if err == nil {
			// Resource still exists - vulnerability is active
			logger.Info("K03 vulnerability still active", "target", targetDeployment,
				"resource", res.name, "reason", res.reason)
			vulnerabilityFound = true
			break // Found one vulnerability, that's enough to know it's not remediated
		} else if !errors.IsNotFound(err) {
			// Unexpected error
			return false, fmt.Errorf("failed to check RBAC resource %s: %w", res.name, err)
		}
		// Resource not found is good - continue checking
	}

	if vulnerabilityFound {
		return false, nil
	}

	logger.Info("K03 vulnerability remediated: overpermissive RBAC resources removed", "target", targetDeployment)
	return true, nil
}

// checkK06 verifies if the authentication vulnerability has been fixed
func checkK06(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K06 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	container := dep.Spec.Template.Spec.Containers[0]
	vulnerabilitiesFound := false

	// Check for auto-mounted service account tokens
	if dep.Spec.Template.Spec.AutomountServiceAccountToken != nil && *dep.Spec.Template.Spec.AutomountServiceAccountToken {
		logger.Info("K06 vulnerability still active: service account token auto-mounting enabled", "target", targetDeployment)
		vulnerabilitiesFound = true
	}

	// Check for hardcoded credentials (look for values that should be from secrets)
	for _, env := range container.Env {
		if env.ValueFrom == nil && env.Value != "" {
			// Check for common secret-like patterns
			if containsSensitiveValue(env.Name, env.Value) {
				logger.Info("K06 vulnerability still active: hardcoded credentials found", "target", targetDeployment, "env", env.Name)
				vulnerabilitiesFound = true
				break
			}
		}
	}

	// Check for default service account usage (empty serviceAccountName)
	if dep.Spec.Template.Spec.ServiceAccountName == "" {
		logger.Info("K06 vulnerability still active: using default service account", "target", targetDeployment)
		vulnerabilitiesFound = true
	}

	// Check for exposed authentication environment variables
	for _, env := range container.Env {
		if isExposedAuthEnv(env.Name, env.Value) {
			logger.Info("K06 vulnerability still active: exposed authentication token", "target", targetDeployment, "env", env.Name)
			vulnerabilitiesFound = true
			break
		}
	}

	// Check for missing fsGroup in PodSecurityContext
	if dep.Spec.Template.Spec.SecurityContext == nil || dep.Spec.Template.Spec.SecurityContext.FSGroup == nil {
		logger.Info("K06 vulnerability still active: missing fsGroup in PodSecurityContext", "target", targetDeployment)
		vulnerabilitiesFound = true
	}

	// Check for containers running as root
	for _, cont := range dep.Spec.Template.Spec.Containers {
		if cont.SecurityContext != nil && cont.SecurityContext.RunAsUser != nil && *cont.SecurityContext.RunAsUser == 0 {
			logger.Info("K06 vulnerability still active: container running as root with volume access", "target", targetDeployment, "container", cont.Name)
			vulnerabilitiesFound = true
			break
		}
	}

	// Check for privileged containers with volume access
	for _, cont := range dep.Spec.Template.Spec.Containers {
		if cont.SecurityContext != nil && cont.SecurityContext.Privileged != nil && *cont.SecurityContext.Privileged {
			logger.Info("K06 vulnerability still active: privileged container with volume access", "target", targetDeployment, "container", cont.Name)
			vulnerabilitiesFound = true
			break
		}
	}

	if vulnerabilitiesFound {
		return false, nil
	}

	logger.Info("K06 vulnerability remediated: authentication configuration is now secure", "target", targetDeployment)
	return true, nil
}

// containsSensitiveValue checks if an environment variable contains sensitive hardcoded values
func containsSensitiveValue(name, value string) bool {
	// Check for database credentials that should be from secrets
	if name == "POSTGRES_USER" && value == "appuser" {
		return true
	}
	if name == "POSTGRES_PASSWORD" && value == "apppassword" {
		return true
	}
	if name == "API_KEY" && value == testAPIKey {
		return true
	}
	return false
}

// isExposedAuthEnv checks if an environment variable exposes authentication tokens
func isExposedAuthEnv(name, value string) bool {
	sensitiveEnvNames := []string{
		"JWT_SECRET", "API_TOKEN", "AUTH_KEY", "SESSION_SECRET",
		"STRIPE_SECRET", "WEBHOOK_SECRET", "AUTH_TOKEN", "SECRET_KEY",
	}

	for _, sensitiveEnv := range sensitiveEnvNames {
		if name == sensitiveEnv && value != "" {
			return true
		}
	}
	return false
}

// checkK07 verifies if the network segmentation vulnerability has been addressed
func checkK07(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment to check annotations
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K07 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	vulnerabilitiesFound := false

	// Check for unrestricted pod communication annotations
	if dep.Spec.Template.Annotations != nil {
		if policy, exists := dep.Spec.Template.Annotations["networking.kubernetes.io/network-policy"]; exists && policy == "disabled" {
			logger.Info("K07 vulnerability still active: network policy disabled", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
		if isolation, exists := dep.Spec.Template.Annotations["networking.kubernetes.io/isolation"]; exists && isolation == "none" {
			logger.Info("K07 vulnerability still active: network isolation disabled", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
	}

	// Check for postgres service exposed as NodePort (vulnerability case 2)
	postgresSvc := &corev1.Service{}
	err = c.Get(ctx, client.ObjectKey{Name: "postgres-service", Namespace: namespace}, postgresSvc)
	if err == nil {
		if postgresSvc.Spec.Type == corev1.ServiceTypeNodePort {
			logger.Info("K07 vulnerability still active: postgres service exposed as NodePort", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
		// Check for the service exposure annotation (vulnerability case 3)
		if postgresSvc.Annotations != nil {
			if exposure, exists := postgresSvc.Annotations["networking.kubernetes.io/exposure"]; exists && exposure == "external-database-access" {
				logger.Info("K07 vulnerability still active: postgres service has exposure annotation", "target", targetDeployment)
				vulnerabilitiesFound = true
			}
		}
	} else if !errors.IsNotFound(err) {
		// Unexpected error accessing postgres service
		return false, fmt.Errorf("failed to check postgres service: %w", err)
	}

	if vulnerabilitiesFound {
		return false, nil
	}

	logger.Info("K07 vulnerability remediated: network segmentation controls are in place", "target", targetDeployment)
	return true, nil
}

// checkK08 verifies if the secrets management vulnerability has been fixed
func checkK08(ctx context.Context, c client.Client, targetDeployment, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	// Get the deployment to check for hardcoded secrets and insecure configurations
	dep := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, dep)
	if err != nil {
		if errors.IsNotFound(err) {
			// The deployment was deleted, which is a valid fix
			logger.Info("K08 vulnerability remediated: target deployment was deleted", "target", targetDeployment)
			return true, nil
		}
		return false, fmt.Errorf("failed to get deployment %s: %w", targetDeployment, err)
	}

	vulnerabilitiesFound := false
	container := dep.Spec.Template.Spec.Containers[0]

	// Check for hardcoded secrets in environment variables
	for _, env := range container.Env {
		if env.ValueFrom == nil && env.Value != "" {
			if isHardcodedSecret(env.Name, env.Value) {
				logger.Info("K08 vulnerability still active: hardcoded secret found", "target", targetDeployment, "env", env.Name)
				vulnerabilitiesFound = true
				break
			}
		}
	}

	// Check for insecure volume permissions
	for _, volume := range dep.Spec.Template.Spec.Volumes {
		if volume.Secret != nil && volume.Secret.DefaultMode != nil {
			mode := *volume.Secret.DefaultMode
			if mode&0077 != 0 { // World or group readable
				logger.Info("K08 vulnerability still active: insecure secret volume permissions", "target", targetDeployment, "mode", fmt.Sprintf("%o", mode))
				vulnerabilitiesFound = true
				break
			}
		}
	}

	// Check for secrets stored in ConfigMaps
	configMapList := &corev1.ConfigMapList{}
	err = c.List(ctx, configMapList, client.InNamespace(namespace))
	if err != nil {
		return false, fmt.Errorf("failed to list ConfigMaps: %w", err)
	}

	for _, cm := range configMapList.Items {
		if strings.Contains(cm.Name, targetDeployment) {
			// Check if ConfigMap contains secret-like data
			for key, value := range cm.Data {
				if isSecretData(key, value) {
					logger.Info("K08 vulnerability still active: secrets found in ConfigMap", "target", targetDeployment, "configmap", cm.Name, "key", key)
					vulnerabilitiesFound = true
					break
				}
			}
		}
		if vulnerabilitiesFound {
			break
		}
	}

	// Check for base64 exposed secrets
	secretList := &corev1.SecretList{}
	err = c.List(ctx, secretList, client.InNamespace(namespace))
	if err != nil {
		return false, fmt.Errorf("failed to list Secrets: %w", err)
	}

	for _, secret := range secretList.Items {
		// Check if secret uses Data field with base64 encoding exposed
		if secret.StringData == nil && secret.Data != nil {
			for key, data := range secret.Data {
				// Check if the data looks like double-encoded base64 (vulnerability)
				if decoded, err := base64.StdEncoding.DecodeString(string(data)); err == nil {
					if isSecretData(key, string(decoded)) {
						logger.Info("K08 vulnerability still active: base64 exposed secret", "target", targetDeployment, "secret", secret.Name, "key", key)
						vulnerabilitiesFound = true
						break
					}
				}
			}
		}
		if vulnerabilitiesFound {
			break
		}
	}

	// Check annotations that indicate vulnerable configurations
	if dep.Spec.Template.Annotations != nil {
		if _, exists := dep.Spec.Template.Annotations["config.kubernetes.io/hardcoded-secrets"]; exists {
			logger.Info("K08 vulnerability still active: hardcoded secrets annotation found", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
		if _, exists := dep.Spec.Template.Annotations["security.kubernetes.io/volume-permissions"]; exists {
			logger.Info("K08 vulnerability still active: insecure volume permissions annotation found", "target", targetDeployment)
			vulnerabilitiesFound = true
		}
	}

	if vulnerabilitiesFound {
		return false, nil
	}

	logger.Info("K08 vulnerability remediated: secrets management is now secure", "target", targetDeployment)
	return true, nil
}

// isHardcodedSecret checks if an environment variable contains a hardcoded secret
func isHardcodedSecret(name, value string) bool {
	// Check for common secret patterns
	secretPatterns := map[string][]string{
		"JWT_SECRET":     {"super-secure-jwt-signing-key-2024"},
		"REDIS_PASSWORD": {"redis-secure-password-123"},
		"API_KEY":        {"sk_test_12345", "sk_live_"},
	}

	if patterns, exists := secretPatterns[name]; exists {
		for _, pattern := range patterns {
			if strings.Contains(value, pattern) {
				return true
			}
		}
	}

	// Generic secret detection
	if strings.Contains(strings.ToLower(name), "secret") ||
		strings.Contains(strings.ToLower(name), "password") ||
		strings.Contains(strings.ToLower(name), "key") {
		if len(value) > 8 && !strings.Contains(value, ":") { // Avoid URLs
			return true
		}
	}

	return false
}

// isSecretData checks if a key-value pair contains secret-like data
func isSecretData(key, value string) bool {
	secretKeys := []string{
		"jwt-secret", "redis-password", "database-url", "api-key",
		"password", "secret", "key", "token", "auth",
	}

	keyLower := strings.ToLower(key)
	for _, secretKey := range secretKeys {
		if strings.Contains(keyLower, secretKey) {
			return len(value) > 5 // Assume secrets are longer than 5 chars
		}
	}

	return false
}
