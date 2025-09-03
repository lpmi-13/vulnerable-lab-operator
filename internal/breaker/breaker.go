package breaker

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lpmi-13/vulnerable-lab-operator/internal/baseline"
)

// BreakCluster applies the specified vulnerability to the cluster
func BreakCluster(ctx context.Context, c client.Client, vulnerabilityID string, targetResource, namespace string) error {
	logger := log.FromContext(ctx)

	logger.Info("Applying vulnerability", "vulnerability", vulnerabilityID, "namespace", namespace)

	// First, ensure the namespace exists
	if err := createNamespaceIfNotExists(ctx, c, namespace); err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Apply the specific vulnerability
	switch vulnerabilityID {
	case "K01":
		return applyK01(ctx, c, targetResource, namespace)
	case "K02":
		return applyK02(ctx, c, targetResource, namespace)
	// case "K03":
	// return applyK03(ctx, c, namespace)
	// ... Add cases for K04, K06, K07, K08, K09, K10
	default:
		return fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}
}

func getEnvironmentVariables(deploymentName string) []corev1.EnvVar {
	baseEnv := []corev1.EnvVar{}

	envMap := map[string][]corev1.EnvVar{
		"api": {
			{Name: "REDIS_URL", Value: "redis-service:6379"},
			{Name: "DATABASE_URL", Value: "postgres-service:5432"},
			{Name: "USER_SERVICE_URL", Value: "http://user-service-svc:8000"},
			{Name: "PAYMENT_SERVICE_URL", Value: "http://payment-service-svc:8080"},
		},
		"webapp": {
			{Name: "API_URL", Value: "http://api-service:3000"},
		},
		"user-service": {
			{Name: "PODINFO_PORT", Value: "8081"},
			{Name: "DATABASE_URL", Value: "postgres-service:5432"},
			{Name: "REDIS_URL", Value: "redis-service:6379"},
			{Name: "SERVICE_NAME", Value: "user-service"},
		},
		"payment-service": {
			{Name: "PODINFO_PORT", Value: "8082"},
			{Name: "DATABASE_URL", Value: "postgres-service:5432"},
			{Name: "REDIS_URL", Value: "redis-service:6379"},
			{Name: "SERVICE_NAME", Value: "payment-service"},
			{Name: "API_KEY", Value: "sk_test_12345"},
		},
	}

	if env, exists := envMap[deploymentName]; exists {
		baseEnv = append(baseEnv, env...)
	}

	return baseEnv
}

func getContainerPorts(deploymentName string) []corev1.ContainerPort {
	ports := map[string][]corev1.ContainerPort{
		"api":             {{ContainerPort: 5000, Name: "http"}},
		"webapp":          {{ContainerPort: 80, Name: "http"}},
		"grafana":         {{ContainerPort: 3000, Name: "http"}},
		"user-service":    {{ContainerPort: 8090, Name: "http"}},
		"payment-service": {{ContainerPort: 8091, Name: "http"}},
	}
	if port, exists := ports[deploymentName]; exists {
		return port
	}
	return []corev1.ContainerPort{{ContainerPort: 8080, Name: "http"}}
}

func getContainerName(deploymentName string) string {
	names := map[string]string{
		"api":             "api-server",
		"webapp":          "web-ui",
		"grafana":         "grafana",
		"user-service":    "user-api",
		"payment-service": "payment-processor",
	}
	if name, exists := names[deploymentName]; exists {
		return name
	}
	return strings.Split(deploymentName, "-")[0]
}

func isMaliciousImage(image, deployment string) bool {
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

	expectedMalicious, exists := maliciousImages[deployment]
	return exists && image == expectedMalicious
}

// Helper function to get malicious images
func getMaliciousImages() map[string]string {
	return map[string]string{
		"api":             "node:14-alpine",
		"webapp":          "nginx:1.18-alpine",
		"user-service":    "python:3.7-alpine",
		"payment-service": "ruby:2.7-alpine",
		"grafana":         "grafana/grafana:8.3.0",
		"prometheus":      "prom/prometheus:v2.30.0",
		"redis-cache":     "redis:5-alpine",
		"postgres-db":     "postgres:13-alpine",
	}
}

func getContainerCommand(deployment, image string) []string {
	// For very old or minimal images, we may need to use sleep infinity
	if strings.Contains(image, "alpine:3.10") {
		return []string{"sleep", "infinity"}
	}

	// For application images, they'll have their own entrypoints
	return nil // Let the image use its default command
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

// applyK01 implements Insecure Workload Configurations for a specific target
func applyK01(ctx context.Context, c client.Client, targetDeployment, namespace string) error {
	logger := log.FromContext(ctx)

	// For K01, we'll create a separate insecure workload rather than modifying existing ones
	// This keeps the pattern consistent with K02
	insecureDeploymentName := "insecure-workload-" + targetDeployment

	// Check if the insecure deployment already exists
	existingDeployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: insecureDeploymentName, Namespace: namespace}, existingDeployment)
	if err == nil {
		logger.Info("K01 insecure deployment already exists", "namespace", namespace)
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check for existing deployment: %w", err)
	}

	// Create a privileged pod deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      insecureDeploymentName,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": insecureDeploymentName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": insecureDeploymentName},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "insecure-container",
							Image: "hashicorp/http-echo",
							Args:  []string{"-text=I'm a privileged container!", "-listen=:8080"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
								RunAsUser:  ptr.To(int64(0)),
							},
						},
					},
				},
			},
		},
	}

	logger.Info("Creating K01 insecure deployment", "target", targetDeployment)
	return c.Create(ctx, deployment)
}

// applyK02 implements Supply Chain Vulnerabilities by deploying outdated images with known CVEs
func applyK02(ctx context.Context, c client.Client, targetDeployment, namespace string) error {
	logger := log.FromContext(ctx)
	logger.Info("Applying K02 supply chain vulnerability", "target", targetDeployment, "namespace", namespace)

	// Check if the deployment already exists
	existingDeployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: targetDeployment, Namespace: namespace}, existingDeployment)

	if err == nil {
		// Deployment exists - check if it already has the malicious image
		currentImage := existingDeployment.Spec.Template.Spec.Containers[0].Image

		// Use a more robust check for malicious images
		maliciousImages := getMaliciousImages()
		expectedMalicious, exists := maliciousImages[targetDeployment]

		if exists && currentImage == expectedMalicious {
			logger.Info("K02 vulnerability already applied", "target", targetDeployment)
			return nil
		}

		// If deployment exists but doesn't have malicious image, we need to update it
		logger.Info("Updating existing deployment with vulnerable image", "target", targetDeployment)
		patch := client.MergeFrom(existingDeployment.DeepCopy())
		existingDeployment.Spec.Template.Spec.Containers[0].Image = expectedMalicious
		return c.Patch(ctx, existingDeployment, patch)
	}

	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check for existing deployment: %w", err)
	}

	// Deployment doesn't exist - create it with malicious image
	maliciousImages := getMaliciousImages()
	maliciousImage, exists := maliciousImages[targetDeployment]
	if !exists {
		maliciousImage = "alpine:3.10"
	}

	// Create the deployment with the malicious image
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      targetDeployment,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": targetDeployment},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": targetDeployment},
					Annotations: map[string]string{
						"deprecated-image": "true",
						"security-scan":    "failed",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    getContainerName(targetDeployment),
							Image:   maliciousImage,
							Command: getContainerCommand(targetDeployment, maliciousImage),
							Ports:   getContainerPorts(targetDeployment),
							Env:     getEnvironmentVariables(targetDeployment),
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("64Mi"),
									corev1.ResourceCPU:    resource.MustParse("50m"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("128Mi"),
									corev1.ResourceCPU:    resource.MustParse("100m"),
								},
							},
						},
					},
				},
			},
		},
	}

	logger.Info("Creating K02 vulnerable deployment", "target", targetDeployment, "image", maliciousImage)
	return c.Create(ctx, deployment)
}
