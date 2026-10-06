# Product contract

## Purpose and user

One operator with approximately 1–5 personal applications needs several genuine Supabase installations on one server. Capacity is bounded by measured host resources; there is no MAX_PROJECTS. Python CLI overhead is small; the Supabase stacks remain substantial workloads.

A long-lived project is an official self-hosted Docker deployment, independently persistent and explicitly backed up and updated. A sandbox is the official Supabase CLI environment scoped to an application repository and deliberately disposable. They have different commands, identifiers, resource ownership and authority.

## V1

Create/list; start/stop/restart; health/status/logs; original Studio URL/open; interactive slash commands and session-only active project; doctor; nonsecret connection information and explicitly privileged environment execution; encrypted backup, verification and restore; explicit pinned updates; deliberate removal; local-only CLI sandbox helpers; additive nginx generation/validation/manual installation instructions. One `standard` profile runs the entire current official base Compose service set, including Storage. No arbitrary override plugins or profile pruning in V1.

Linux with local Docker Engine is the supported production host. Core operations run as an ordinary user already authorized to use Docker. No implicit sudo. Mac/Windows hosting, remote Docker contexts, rootless/Podman edge cases and external Storage backends are outside V1 support.

## Not now

No frontend, custom Studio, backend/API server, daemon, control-plane DB, Redis, queues, accounts, organizations, teams/roles, SaaS, billing, multi-host coordination, clustering/failover, Kubernetes, Terraform provider, Ansible collection, plugin framework/marketplace, monitoring/alerting platform, Prometheus/Grafana, capacity prediction/autoscaling, backup scheduler/UI, Cloud management, Cloudflare automation or certificate provisioning platform. No general-purpose container orchestrator or database proxy. No automatic unattended updates.

## Definition of DONE

**Release criteria:** mandatory gates in [TESTING_STRATEGY.md](TESTING_STRATEGY.md) must pass before a semver release is tagged. Two simultaneous projects must have independently working Studio, DB and Auth data, different secrets, isolated storage and lifecycle. Backup must survive a disposable restore and subsequent object/API checks. Updating must not bypass backup or isolation validation. Sandbox reset/destroy needs no Cloud credentials and cannot target a linked/remote DB through the wrapper. Doctor detects actual failure. Package build, lint, unit/process tests and integration acceptance pass. WAITING_EXTERNAL / OPTIONAL gates are honest incompletion, never DONE.

SBfleet is an independent open-source project and is not affiliated with, sponsored by, or endorsed by Supabase.
