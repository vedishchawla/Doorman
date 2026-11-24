# Doorman Kubernetes Deployment (Zero-Trust Cloud-Native Architecture)

This directory packages Doorman for Kubernetes (Docker Desktop Kubernetes, kind, minikube, or managed EKS/GKE/AKS).

## Zero-Trust Controls in Kubernetes
1. **Default-Deny `NetworkPolicy` (`07-network-policies.yaml`)**: Blocks all lateral pod-to-pod ingress by default. Only `nginx-ingress` can reach `doorman-proxy`, and only `doorman-proxy` can reach `opa`, `keycloak`, `backend-a`, and `backend-b`.
2. **Double Workload Isolation**: Even inside the cluster, `backend-a` and `backend-b` enforce mutual TLS (`doorman-mtls-certs` Secret).
3. **Hardened Non-Root Distroless Proxy (`05-proxy.yaml`)**: Runs as UID `65532` with `readOnlyRootFilesystem: true`, dropped Linux capabilities, readiness/liveness probes, Prometheus scrape annotations on `:9090`, and a `HorizontalPodAutoscaler` (`2–10` pods at 70% CPU).

## Quick Commands

```bash
# Validate manifests client-side
kubectl apply --dry-run=client -f k8s/

# Build local images for Docker Desktop Kubernetes / kind
docker build -t doorman-proxy:latest .
docker build -t doorman-backend:latest ./backends

# Create Secrets & ConfigMaps from existing repo artifacts
kubectl apply -f k8s/00-namespace.yaml
kubectl -n doorman create configmap keycloak-realm --from-file=realm-export.json=keycloak/realm-export.json
kubectl -n doorman create secret generic doorman-mtls-certs --from-file=certs/mtls/
kubectl -n doorman create secret generic doorman-edge-certs --from-file=nginx/certs/
kubectl -n doorman create secret generic doorman-secrets \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD=admin \
  --from-literal=OIDC_CLIENT_SECRET=zt-proxy-dev-secret \
  --from-literal=COOKIE_SECRET=zt-proxy-compose-cookie-secret-32-bytes \
  --from-literal=POSTURE_PUBLIC_KEY="$(grep POSTURE_PUBLIC_KEY .env | cut -d= -f2-)"

# Deploy full stack
kubectl apply -f k8s/

# Inspect Zero-Trust pods, HPA, and NetworkPolicies
kubectl get pods,svc,hpa,netpol -n doorman
```
