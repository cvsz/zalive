# Cloudflare and Terraform ownership

This template does not ship Cloudflare Terraform. Public DNS records and tunnel
ingress must have exactly one owning repository, and that repository is the only
place they may be declared.

## The rule

| | |
|---|---|
| Owner | the single repository your organization designates for edge infrastructure |
| Scope | every public DNS record and every shared-tunnel ingress route |
| This repository may | declare application code, containers, and its own runtime configuration |
| This repository must not | contain `cloudflare_dns_record`, `cloudflare_tunnel`, `cfargotunnel.com`, or a per-project `infrastructure/terraform/cloudflare` |

Replace the owner above with whatever your organization actually uses. The rest
of this document is written against a worked example, so adapt the names.

### Worked example

In one organization the owner is a separate infrastructure repository, and it
serves every hostname under a single zone and a single tunnel. The steps below
use `service.example.com` as a stand-in for a real hostname.

Two copies of the same record is not a harmless redundancy. It produces
configuration that cannot reproduce reality, and a `plan` in the wrong
repository proposes creating records another repository already owns. That has
happened in practice: a live record was owned by the infrastructure repository
while a declaration in a different repository was never applied, so the two
drifted apart and the live record pointed at the wrong tunnel.

## Requesting a hostname

1. Confirm the service is running and healthy on a loopback port on the
   target host.
2. Create a feature branch in the **owning** repository and add the declaration
   there, following an existing file in its Cloudflare directory:
   - a hostname variable validated as a subdomain of the zone,
   - an origin variable validated to a loopback address, and pinned to the
     reviewed port so it cannot drift to another listener,
   - a `cloudflare_dns_record` pointing at the shared tunnel target,
   - a matching entry in the tunnel ingress list,
   - a URL output.
3. Check whether a record already exists. If it does, **adopt it**:

   ```bash
   terraform import cloudflare_dns_record.<name> "<zone_id>/<record_id>"
   ```

   Importing is always correct. Creating will fail with a duplicate-record
   error, and deleting first would briefly take the hostname offline.
4. Run `terraform plan` and confirm `0 to destroy`. A plan that proposes
   destroying anything unrelated means the branch is based on a config that
   does not match the applied state. Stop and rebase; do not apply it.
5. Open a pull request and let it clear review and required checks.
6. **Only after the pull request merges**, apply the plan on the branch that is
   now `main`, then verify the public route and re-check the other hostnames on
   the same tunnel for regressions.

### Why apply comes after merge

A shared tunnel also serves production hostnames that this change does not
mention, so a careless ingress edit has a wider blast radius than the new
hostname. Reviewing only the rendered diff, while the live tunnel is still
untouched, is the point at which a mistake is still free.

Applying before the review completes means the risky change reaches production
first and the review only decides whether to keep it. If that ordering is
unavoidable — for example a hostname is genuinely urgent — then apply on a
branch that the reviewer can inspect first, and say so explicitly in the pull
request instead of merging unreviewed config.

## Keeping one ingress list

If the owning repository can either manage the tunnel config in Terraform or
hand the operator an ingress fragment to merge by hand, do not write the
hostname list twice. A copy that is maintained by hand will drift, and the
failure is silent: DNS records exist, but requests fall through to the
terminal catch-all route and return `http_status:404`.

Declare the routes once, in a shared local value, and read it from both the
managed tunnel config and the operator-facing output.

## If the project needs a separate tunnel

Do not create one by default. A separate tunnel means another connector, its
own credential, and another thing to keep alive across reboots. Raise it
first, and expect to justify why the shared tunnel is not sufficient.

## Local development

Terraform is not run from this project. `terraform plan` requires the operator
credentials that live in the owning repository's host configuration, and the
state is not part of this repository.
