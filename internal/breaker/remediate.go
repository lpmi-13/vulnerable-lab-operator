package breaker

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// CheckRemediation verifies if the specified vulnerability has been fixed
func CheckRemediation(ctx context.Context, c client.Client, vulnerabilityID string, labName string) (bool, error) {
	namespace := getLabNamespace(labName)

	switch vulnerabilityID {
	case "K01":
		return checkK01(ctx, c, namespace)
	// case "K02":
	// return checkK02(ctx, c, namespace)
	// case "K03":
	// return checkK03(ctx, c, namespace)
	// ... Add cases for other vulnerabilities
	default:
		return false, fmt.Errorf("unknown vulnerability ID: %s", vulnerabilityID)
	}
}

// checkK01 verifies if the privileged deployment has been fixed
func checkK01(ctx context.Context, c client.Client, namespace string) (bool, error) {
	logger := log.FromContext(ctx)

	deployment := &appsv1.Deployment{}
	err := c.Get(ctx, client.ObjectKey{Name: "insecure-workload", Namespace: namespace}, deployment)
	if err != nil {
		// If the deployment is gone, maybe it was deleted as part of remediation
		return true, nil
	}

	// Check if the pod spec is still privileged
	if deployment.Spec.Template.Spec.Containers[0].SecurityContext != nil &&
		deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged != nil &&
		*deployment.Spec.Template.Spec.Containers[0].SecurityContext.Privileged {

		logger.Info("K01 vulnerability still exists: container is privileged")
		return false, nil
	}

	logger.Info("K01 vulnerability has been remediated!")
	return true, nil
}
