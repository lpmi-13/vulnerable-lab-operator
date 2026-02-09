package breaker

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPreserveImmutableFieldsService(t *testing.T) {
	// Create an existing service with ClusterIP and ClusterIPs set
	existingSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.1",
			ClusterIPs: []string{"10.96.0.1"},
			Type:       corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Port: 80,
				},
			},
		},
	}

	// Create a new service with different ClusterIP values (should be overwritten)
	newSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.2",
			ClusterIPs: []string{"10.96.0.2"},
			Type:       corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{
					Port: 8080,
				},
			},
		},
	}

	// Preserve immutable fields
	preserveImmutableFields(newSvc, existingSvc)

	// Verify ClusterIP was copied from existing
	if newSvc.Spec.ClusterIP != existingSvc.Spec.ClusterIP {
		t.Errorf("ClusterIP not preserved: expected %s, got %s", existingSvc.Spec.ClusterIP, newSvc.Spec.ClusterIP)
	}

	// Verify ClusterIPs was copied from existing
	if len(newSvc.Spec.ClusterIPs) != len(existingSvc.Spec.ClusterIPs) {
		t.Errorf("ClusterIPs length differs: expected %d, got %d", len(existingSvc.Spec.ClusterIPs), len(newSvc.Spec.ClusterIPs))
	} else {
		for i := range existingSvc.Spec.ClusterIPs {
			if newSvc.Spec.ClusterIPs[i] != existingSvc.Spec.ClusterIPs[i] {
				t.Errorf("ClusterIPs[%d] not preserved: expected %s, got %s", i, existingSvc.Spec.ClusterIPs[i], newSvc.Spec.ClusterIPs[i])
			}
		}
	}

	// Verify other fields weren't affected
	if newSvc.Spec.Type != corev1.ServiceTypeNodePort {
		t.Error("Service type should not be changed by preserveImmutableFields")
	}
	if len(newSvc.Spec.Ports) != 1 || newSvc.Spec.Ports[0].Port != 8080 {
		t.Error("Service ports should not be changed by preserveImmutableFields")
	}
}

func TestPreserveImmutableFieldsNonService(t *testing.T) {
	// Test that non-Service types don't panic
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"key": "value",
		},
	}

	newConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"key": "newvalue",
		},
	}

	// Should not panic for non-Service types
	preserveImmutableFields(newConfigMap, existingConfigMap)

	// Verify data wasn't changed (since ConfigMap has no immutable fields handled by this function)
	if newConfigMap.Data["key"] != "newvalue" {
		t.Error("ConfigMap data should not be changed by preserveImmutableFields")
	}
}

// Test that preserveImmutableFields handles the generic client.Object interface correctly
func TestPreserveImmutableFieldsInterface(t *testing.T) {
	existingSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "10.96.0.1",
			ClusterIPs: []string{"10.96.0.1"},
		},
	}

	newSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-service",
			Namespace: "test-ns",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "",
			ClusterIPs: nil,
		},
	}

	// Use client.Object interface
	var newObj client.Object = newSvc
	var existingObj client.Object = existingSvc

	preserveImmutableFields(newObj, existingObj)

	// Verify fields were preserved
	newSvcTyped := newObj.(*corev1.Service)
	if newSvcTyped.Spec.ClusterIP != "10.96.0.1" {
		t.Error("ClusterIP not preserved when using client.Object interface")
	}
}
