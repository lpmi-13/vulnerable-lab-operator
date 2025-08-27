package baseline

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetAppStack returns a complete application stack of Kubernetes objects for the given namespace.
// This represents the "healthy" baseline state before any vulnerabilities are applied.
func GetAppStack(namespace string) []client.Object {
	pathPrefix := networkingv1.PathTypePrefix

	return []client.Object{
		// 1. Redis Cache
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "redis-cache",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "cache"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "redis-cache", "app.kubernetes.io/component": "cache"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "redis-cache", "app.kubernetes.io/component": "cache"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "redis",
								Image: "redis:7.2-alpine", // Use a specific, recent version
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 6379,
										Name:          "redis",
									},
								},
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
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "redis-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "cache"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "redis-cache"},
				Ports: []corev1.ServicePort{
					{
						Port:       6379,
						TargetPort: intstr.FromString("redis"),
						Name:       "redis",
					},
				},
			},
		},

		// 2. API Service
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api", "app.kubernetes.io/component": "backend"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "api", "app.kubernetes.io/component": "backend"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "api-server",
								Image: "ghcr.io/stefanprodan/podinfo:6.5.2", // A popular, simple demo API
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 9898,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "REDIS_URL",
										Value: "redis-service:6379",
									},
								},
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
								LivenessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/healthz",
											Port: intstr.FromString("http"),
										},
									},
									InitialDelaySeconds: 5,
									PeriodSeconds:       10,
								},
								ReadinessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										HTTPGet: &corev1.HTTPGetAction{
											Path: "/readyz",
											Port: intstr.FromString("http"),
										},
									},
									InitialDelaySeconds: 5,
									PeriodSeconds:       10,
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "api"},
				Ports: []corev1.ServicePort{
					{
						Port:       80,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 3. Web App Frontend
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webapp",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "frontend"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "webapp", "app.kubernetes.io/component": "frontend"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "webapp", "app.kubernetes.io/component": "frontend"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name:  "web-ui",
								Image: "nginx:1.25-alpine", // Simple static server
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 80,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "API_URL",
										Value: "http://api-service:80",
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory: resource.MustParse("32Mi"),
										corev1.ResourceCPU:    resource.MustParse("10m"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory: resource.MustParse("64Mi"),
										corev1.ResourceCPU:    resource.MustParse("50m"),
									},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webapp-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "frontend"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "webapp"},
				Ports: []corev1.ServicePort{
					{
						Port:       80,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 4. Ingress - Route traffic to the webapp
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-ingress",
				Namespace: namespace,
			},
			Spec: networkingv1.IngressSpec{
				IngressClassName: ptr.To("traefik"), // k3s uses traefik by default
				Rules: []networkingv1.IngressRule{
					{
						Host: "app.local", // You'll need to add this to your /etc/hosts or use a real DNS
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/",
										PathType: &pathPrefix,
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "webapp-service",
												Port: networkingv1.ServiceBackendPort{Number: 80},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
