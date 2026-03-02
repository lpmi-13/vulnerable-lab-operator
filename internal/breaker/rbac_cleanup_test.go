package breaker

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCleanupLabManagedRBAC(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add corev1 scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add rbacv1 scheme: %v", err)
	}

	labNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-lab"}}
	otherNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other-ns"}}

	labeledRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-lab-secrets-access-role",
			Namespace: "test-lab",
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
		},
	}
	labeledRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-lab-secrets-access-binding",
			Namespace: "test-lab",
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
		},
	}
	unlabeledRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "keep-role",
			Namespace: "test-lab",
		},
	}
	otherNamespaceRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-lab-role",
			Namespace: "other-ns",
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
		},
	}
	labeledCR := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-lab-cluster-role",
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
		},
	}
	labeledCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-lab-cluster-binding",
			Labels: map[string]string{
				"rbac.k8s.lab/managed-by": "vulnerable-lab",
			},
		},
	}
	unlabeledCR := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "keep-cluster-role",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			labNS,
			otherNS,
			labeledRole,
			labeledRB,
			unlabeledRole,
			otherNamespaceRole,
			labeledCR,
			labeledCRB,
			unlabeledCR,
		).
		Build()

	if err := cleanupLabManagedRBAC(context.Background(), c, "test-lab"); err != nil {
		t.Fatalf("cleanupLabManagedRBAC failed: %v", err)
	}

	assertNotFound := func(obj ctrlclient.Object) {
		t.Helper()
		err := c.Get(context.Background(), types.NamespacedName{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}, obj)
		if err == nil {
			t.Fatalf("expected %T/%s to be deleted", obj, obj.GetName())
		}
	}
	assertExists := func(obj ctrlclient.Object) {
		t.Helper()
		err := c.Get(context.Background(), types.NamespacedName{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
		}, obj)
		if err != nil {
			t.Fatalf("expected %T/%s to exist: %v", obj, obj.GetName(), err)
		}
	}

	assertNotFound(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: labeledRole.Name, Namespace: "test-lab"}})
	assertNotFound(&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: labeledRB.Name, Namespace: "test-lab"}})
	assertNotFound(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: labeledCR.Name}})
	assertNotFound(&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: labeledCRB.Name}})

	assertExists(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: unlabeledRole.Name, Namespace: "test-lab"}})
	assertExists(&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: otherNamespaceRole.Name, Namespace: "other-ns"}})
	assertExists(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: unlabeledCR.Name}})
}
