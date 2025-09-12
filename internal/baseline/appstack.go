package baseline

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getSecureSecurityContext returns a secure security context for non-root containers
func getSecureSecurityContext(uid int64) *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsUser:                ptr.To(uid),
		RunAsGroup:               ptr.To(uid),
		RunAsNonRoot:             ptr.To(true),
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
}

func GetAppStack(namespace string) []client.Object {
	pathPrefix := networkingv1.PathTypePrefix

	return []client.Object{
		// 1. PostgreSQL Database
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "postgres-db",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "database"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "postgres-db", "app.kubernetes.io/component": "database"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "postgres-db", "app.kubernetes.io/component": "database"},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "postgres",
								Image:           "postgres:17-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 5432,
										Name:          "postgres",
									},
								},
								SecurityContext: &corev1.SecurityContext{
									RunAsUser:                ptr.To(int64(10001)), // postgres user
									RunAsGroup:               ptr.To(int64(10001)), // postgres group
									RunAsNonRoot:             ptr.To(true),
									AllowPrivilegeEscalation: ptr.To(false),
									ReadOnlyRootFilesystem:   ptr.To(true),
									Capabilities: &corev1.Capabilities{
										Drop: []corev1.Capability{"ALL"},
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "PGDATA",
										Value: "/var/lib/postgresql/data/pgdata",
									},
									{
										Name:  "POSTGRES_INITDB_ARGS",
										Value: "--auth-host=trust",
									},
									{
										Name:  "POSTGRES_DB",
										Value: "appdb",
									},
									{
										Name: "POSTGRES_USER",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "postgres-credentials",
												},
												Key: "username",
											},
										},
									},
									{
										Name: "POSTGRES_PASSWORD",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "postgres-credentials",
												},
												Key: "password",
											},
										},
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("256Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("512Mi"),
										corev1.ResourceCPU:              resource.MustParse("200m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "postgres-data",
										MountPath: "/var/lib/postgresql/data",
									},
									{
										Name:      "postgres-tmp",
										MountPath: "/tmp",
									},
									{
										Name:      "postgres-var-tmp",
										MountPath: "/var/tmp",
									},
									{
										Name:      "postgres-run",
										MountPath: "/var/run/postgresql",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "postgres-data",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: "postgres-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: "postgres-var-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: "postgres-run",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
						SecurityContext: &corev1.PodSecurityContext{
							FSGroup: ptr.To(int64(10001)), // postgres group - ensures volume is writable by postgres user
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "postgres-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "database"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "postgres-db"},
				Ports: []corev1.ServicePort{
					{
						Port:       5432,
						TargetPort: intstr.FromString("postgres"),
						Name:       "postgres",
					},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "postgres-credentials",
				Namespace: namespace,
			},
			StringData: map[string]string{
				"username": "appuser",
				"password": "apppassword",
			},
			Type: corev1.SecretTypeOpaque,
		},

		// 2. Redis Cache
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
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "redis",
								Image:           "redis:8.2-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 6379,
										Name:          "redis",
									},
								},
								SecurityContext: getSecureSecurityContext(10002), // redis user
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "redis-tmp",
										MountPath: "/tmp",
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("64Mi"),
										corev1.ResourceCPU:              resource.MustParse("50m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("128Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("512Mi"),
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "redis-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
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

		// 3. Prometheus Monitoring
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "monitoring"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "prometheus", "app.kubernetes.io/component": "monitoring"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "prometheus", "app.kubernetes.io/component": "monitoring"},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "prometheus",
								Image:           "prom/prometheus:v3.5.0",
								ImagePullPolicy: corev1.PullAlways,
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 9090,
										Name:          "http",
									},
								},
								Args: []string{
									"--config.file=/etc/prometheus/prometheus.yml",
									"--storage.tsdb.path=/prometheus",
									"--web.console.libraries=/etc/prometheus/console_libraries",
									"--web.console.templates=/etc/prometheus/consoles",
									"--web.enable-lifecycle",
								},
								SecurityContext: getSecureSecurityContext(65534), // nobody user
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("256Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("512Mi"),
										corev1.ResourceCPU:              resource.MustParse("200m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "prometheus-config",
										MountPath: "/etc/prometheus",
									},
									{
										Name:      "prometheus-data",
										MountPath: "/prometheus",
									},
									{
										Name:      "prometheus-tmp",
										MountPath: "/tmp",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "prometheus-config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "prometheus-config",
										},
									},
								},
							},
							{
								Name: "prometheus-data",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: "prometheus-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "monitoring"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "prometheus"},
				Ports: []corev1.ServicePort{
					{
						Port:       9090,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 4. Prometheus ConfigMap
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus-config",
				Namespace: namespace,
			},
			Data: map[string]string{
				"prometheus.yml": `
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'api'
    static_configs:
      - targets: ['api-service:9898']

  - job_name: 'webapp'
    static_configs:
      - targets: ['webapp-service:3000']
`,
			},
		},

		// 5. Grafana Dashboard
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grafana",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "monitoring"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "grafana", "app.kubernetes.io/component": "monitoring"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "grafana", "app.kubernetes.io/component": "monitoring"},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "grafana",
								Image:           "grafana/grafana:12.2.0-17630182352-ubuntu",
								ImagePullPolicy: corev1.PullAlways,
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 3000,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name: "GF_SECURITY_ADMIN_USER",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "grafana-credentials",
												},
												Key: "admin-user",
											},
										},
									},
									{
										Name: "GF_SECURITY_ADMIN_PASSWORD",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "grafana-credentials",
												},
												Key: "admin-password",
											},
										},
									},
									{
										Name:  "GF_USERS_ALLOW_SIGN_UP",
										Value: "false",
									},
								},
								SecurityContext: getSecureSecurityContext(10004), // grafana user
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("256Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("512Mi"),
										corev1.ResourceCPU:              resource.MustParse("200m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "grafana-data",
										MountPath: "/var/lib/grafana",
									},
									{
										Name:      "grafana-tmp",
										MountPath: "/tmp",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "grafana-data",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
							{
								Name: "grafana-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grafana-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "monitoring"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "grafana"},
				Ports: []corev1.ServicePort{
					{
						Port:       3000,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 6. API Service
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
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "api-server",
								Image:           "node:22-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Command:         []string{"sleep", "infinity"}, // Keep container running
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 5000,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "REDIS_URL",
										Value: "redis-service:6379",
									},
									{
										Name:  "DATABASE_URL",
										Value: "postgres-service:5432",
									},
									{
										Name:  "USER_SERVICE_URL",
										Value: "http://user-service-svc:8090",
									},
									{
										Name:  "PAYMENT_SERVICE_URL",
										Value: "http://payment-service-svc:8091",
									},
									{
										Name: "JWT_SECRET",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "api-secrets",
												},
												Key: "jwt-secret",
											},
										},
									},
									{
										Name: "REDIS_PASSWORD",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "redis-auth",
												},
												Key: "password",
											},
										},
									},
								},
								SecurityContext: getSecureSecurityContext(10005), // node user
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "api-tmp",
										MountPath: "/tmp",
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("64Mi"),
										corev1.ResourceCPU:              resource.MustParse("50m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("128Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("512Mi"),
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "api-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
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
						Port:       5000,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 7. User Service
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend", "app.kubernetes.io/microservice": "user"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "user-service", "app.kubernetes.io/component": "backend"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "user-service", "app.kubernetes.io/component": "backend"},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "user-api",
								Image:           "python:3.13-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Command:         []string{"sleep", "infinity"},
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 8090,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "DATABASE_URL",
										Value: "postgres-service:5432",
									},
									{
										Name:  "REDIS_URL",
										Value: "redis-service:6379",
									},
									{
										Name:  "SERVICE_NAME",
										Value: "user-service",
									},
								},
								SecurityContext: getSecureSecurityContext(10006), // python user
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("64Mi"),
										corev1.ResourceCPU:              resource.MustParse("50m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("128Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("512Mi"),
									},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "user-config",
										MountPath: "/etc/secrets",
										ReadOnly:  true,
									},
									{
										Name:      "user-tmp",
										MountPath: "/tmp",
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "user-config",
								VolumeSource: corev1.VolumeSource{
									Secret: &corev1.SecretVolumeSource{
										SecretName:  "api-secrets",
										DefaultMode: ptr.To(int32(0400)),
									},
								},
							},
							{
								Name: "user-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-service-svc",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend", "app.kubernetes.io/microservice": "user"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "user-service"},
				Ports: []corev1.ServicePort{
					{
						Port:       8090,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 8. Payment Service
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "payment-service",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend", "app.kubernetes.io/microservice": "payment"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "payment-service", "app.kubernetes.io/component": "backend"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "payment-service", "app.kubernetes.io/component": "backend"},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "payment-processor",
								Image:           "ruby:3.3-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Command:         []string{"sleep", "infinity"},
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 8091,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "DATABASE_URL",
										Value: "postgres-service:5432",
									},
									{
										Name:  "REDIS_URL",
										Value: "redis-service:6379",
									},
									{
										Name:  "SERVICE_NAME",
										Value: "payment-service",
									},
									{
										Name: "API_KEY",
										ValueFrom: &corev1.EnvVarSource{
											SecretKeyRef: &corev1.SecretKeySelector{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "payment-api-key",
												},
												Key: "key",
											},
										},
									},
								},
								SecurityContext: getSecureSecurityContext(10007), // ruby user
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "payment-tmp",
										MountPath: "/tmp",
									},
								},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("64Mi"),
										corev1.ResourceCPU:              resource.MustParse("50m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("128Mi"),
										corev1.ResourceCPU:              resource.MustParse("100m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("512Mi"),
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "payment-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "payment-service-svc",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend", "app.kubernetes.io/microservice": "payment"},
			},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "payment-service"},
				Ports: []corev1.ServicePort{
					{
						Port:       8091,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "payment-api-key",
				Namespace: namespace,
			},
			StringData: map[string]string{
				"key": "sk_test_12345",
			},
			Type: corev1.SecretTypeOpaque,
		},

		// API Service Secrets
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-secrets",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "backend"},
			},
			StringData: map[string]string{
				"jwt-secret": "super-secure-jwt-signing-key-2024",
			},
			Type: corev1.SecretTypeOpaque,
		},

		// Redis Authentication Secret
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "redis-auth",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "cache"},
			},
			StringData: map[string]string{
				"password": "redis-secure-password-123",
			},
			Type: corev1.SecretTypeOpaque,
		},

		// Grafana Credentials Secret
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grafana-credentials",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "monitoring"},
			},
			StringData: map[string]string{
				"admin-user":     "admin",
				"admin-password": "admin",
			},
			Type: corev1.SecretTypeOpaque,
		},

		// TLS Certificates Secret
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-certificates",
				Namespace: namespace,
			},
			StringData: map[string]string{
				"tls.crt": "-----BEGIN CERTIFICATE-----\nMIICDzCCAXgCAQAwDQYJKoZIhvcNAQEFBQAwFTETMBEGA1UEAwwKbXlkb21haW4u\n...\n-----END CERTIFICATE-----",
				"tls.key": "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK9Z...\n-----END PRIVATE KEY-----",
			},
			Type: corev1.SecretTypeTLS,
		},

		// Webapp Nginx Configuration
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webapp-nginx-config",
				Namespace: namespace,
				Labels:    map[string]string{"app.kubernetes.io/component": "frontend"},
			},
			Data: map[string]string{
				"nginx.conf": `# Run nginx as non-root user
# PID file in writable location
pid /tmp/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Use /tmp for cache directories (writable by non-root)
    proxy_temp_path /tmp/proxy_temp;
    client_body_temp_path /tmp/client_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen 8080;
        listen [::]:8080;
        server_name localhost;

        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}`,
			},
		},

		// 9. Web App Frontend
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
						ServiceAccountName: "restricted-sa",
						Containers: []corev1.Container{
							{
								Name:            "web-ui",
								Image:           "nginx:1.29.1-alpine",
								ImagePullPolicy: corev1.PullAlways,
								Ports: []corev1.ContainerPort{
									{
										ContainerPort: 8080,
										Name:          "http",
									},
								},
								Env: []corev1.EnvVar{
									{
										Name:  "API_URL",
										Value: "http://api-service:9898",
									},
								},
								SecurityContext: getSecureSecurityContext(10008), // nginx user
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "nginx-config",
										MountPath: "/etc/nginx/nginx.conf",
										SubPath:   "nginx.conf",
									},
									{
										Name:      "nginx-tmp",
										MountPath: "/tmp",
									},
								},
								Command: []string{"nginx", "-g", "daemon off;"},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("32Mi"),
										corev1.ResourceCPU:              resource.MustParse("10m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("128Mi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceMemory:           resource.MustParse("64Mi"),
										corev1.ResourceCPU:              resource.MustParse("50m"),
										corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "nginx-config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "webapp-nginx-config",
										},
									},
								},
							},
							{
								Name: "nginx-tmp",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
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
						Port:       8080,
						TargetPort: intstr.FromString("http"),
						Name:       "http",
					},
				},
			},
		},

		// 10. Ingress - Route traffic to the webapp and monitoring tools
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-ingress",
				Namespace: namespace,
			},
			Spec: networkingv1.IngressSpec{
				IngressClassName: ptr.To("traefik"),
				Rules: []networkingv1.IngressRule{
					{
						Host: "app.local",
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/",
										PathType: &pathPrefix,
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "webapp-service",
												Port: networkingv1.ServiceBackendPort{Number: 8080},
											},
										},
									},
									{
										Path:     "/grafana",
										PathType: &pathPrefix,
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "grafana-service",
												Port: networkingv1.ServiceBackendPort{Number: 3000},
											},
										},
									},
									{
										Path:     "/prometheus",
										PathType: &pathPrefix,
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "prometheus-service",
												Port: networkingv1.ServiceBackendPort{Number: 9090},
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

		// Network Policies for proper segmentation
		// API Network Policy - allows bidirectional traffic with backend services and data stores
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "api"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "webapp"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "redis-cache"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "postgres-db"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "user-service"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "payment-service"},
								},
							},
						},
					},
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// WebApp Network Policy - only communicates with API
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webapp-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "webapp"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						// Allow ingress traffic (from ingress controller)
						From: []networkingv1.NetworkPolicyPeer{},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
						},
					},
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// Prometheus Network Policy - receives metrics from services
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "prometheus"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "webapp"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "user-service"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "payment-service"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "grafana"},
								},
							},
						},
					},
					// Allow ingress traffic (from ingress controller)
					{
						From: []networkingv1.NetworkPolicyPeer{},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// Grafana Network Policy - communicates with prometheus
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grafana-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "grafana"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						// Allow ingress traffic (from ingress controller)
						From: []networkingv1.NetworkPolicyPeer{},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "prometheus"},
								},
							},
						},
					},
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// PostgreSQL Network Policy - only receives from backend services
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "postgres-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "postgres-db"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "user-service"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "payment-service"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// Redis Network Policy - only receives from API
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "redis-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "redis-cache"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// User Service Network Policy - communicates with API and database
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-service-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "user-service"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "prometheus"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "postgres-db"},
								},
							},
						},
					},
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// Payment Service Network Policy - communicates with API and database
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "payment-service-network-policy",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "payment-service"},
				},
				PolicyTypes: []networkingv1.PolicyType{
					networkingv1.PolicyTypeIngress,
					networkingv1.PolicyTypeEgress,
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "api"},
								},
							},
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "prometheus"},
								},
							},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "postgres-db"},
								},
							},
						},
					},
					// Allow DNS resolution
					{
						To: []networkingv1.NetworkPolicyPeer{
							{
								NamespaceSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"name": "kube-system"},
								},
							},
						},
						Ports: []networkingv1.NetworkPolicyPort{
							{
								Protocol: ptr.To(corev1.ProtocolUDP),
								Port:     ptr.To(intstr.FromInt(53)),
							},
						},
					},
				},
			},
		},

		// Minimal Role for restricted-sa with no secret access
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "restricted-role",
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
		},

		// RoleBinding for restricted-sa
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "restricted-binding",
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "restricted-sa",
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "restricted-role",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},

		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "restricted-sa",
				Namespace: namespace,
			},
		},
	}
}
