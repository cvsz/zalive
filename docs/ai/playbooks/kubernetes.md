# Kubernetes

Confirm context before mutation:

```bash
kubectl config current-context
kubectl version
kubectl get nodes -o wide
kubectl get pods -A
kubectl get events -A --sort-by=.lastTimestamp
```

Review probes, resources, replicas, PDBs, RBAC, service accounts, secrets, network policy, storage, ingress and image provenance.

Prefer `kubectl diff` and `kubectl apply --dry-run=server` before apply. Inspect Helm values/history before upgrade.

Stop on wrong context, destructive storage risk, broad accidental impact, secret exposure, uncertain migration state or critical changes without rollback.
