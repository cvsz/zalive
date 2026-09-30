# Albert Alerts

This document defines Prometheus alerting rules for the Albert activation server.

## ActivationFailuresHigh

- **Description**: High rate of activation failures.
- **Severity**: critical
- **PromQL**: `rate(albert_activation_failures_total[5m]) > 0.05`
- **For**: 5m
- **Expression**:
  ```promql
  rate(albert_activation_failures_total[5m]) > 0.05
  ```
- **Labels**: `severity="critical"`
- **Annotations**:
  - summary: "Albert activation failures > 5% for 5m"
  - description: "Failures rate is {{ $value }} (threshold 0.05)"

Alternative shorthand (as specified in task):
```
rate(failures[5m])>0.05  -> rate(albert_activation_failures_total[5m])>0.05
```

## AlbertDown

- **Description**: Albert server is down.
- **Severity**: critical
- **PromQL**: `albert_up == 0`
- **For**: 1m
- **Expression**:
  ```promql
  albert_up == 0
  ```
- **Labels**: `severity="critical"`
- **Annotations**:
  - summary: "Albert server down"
  - description: "albert_up is 0, server not ready"

Shorthand:
```
albert_up==0
```

## Additional Notes

- Metrics source: `/metrics` endpoint exposes `albert_up`, `albert_activation_total`, `albert_activation_failures_total`, and `albert_request_latency_seconds_bucket` (histogram).
- Dashboard: `grafana/dashboards/albert.json` (single panel with albert_up + activations + latency histogram).
- Tracing: OpenTelemetry optional via `OTEL_EXPORTER_OTLP_ENDPOINT`; deviceActivation spans include redacted `udid` and `productType` attributes.

## Prometheus Rule Example

```yaml
groups:
  - name: albert
    rules:
      - alert: ActivationFailuresHigh
        expr: rate(albert_activation_failures_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Albert activation failures high"
      - alert: AlbertDown
        expr: albert_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Albert down"
```
