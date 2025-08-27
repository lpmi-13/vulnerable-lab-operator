package baseline

const (
	RedisImage   = "redis:7.2-alpine"
	APIImage     = "ghcr.io/stefanprodan/podinfo:6.5.2"
	WebappImage  = "nginx:1.25-alpine"
	IngressClass = "traefik"
	IngressHost  = "app.local"
)
