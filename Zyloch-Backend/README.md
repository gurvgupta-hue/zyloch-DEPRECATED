# Zyloch-Backend

Express API and tenant BFF for Zyloch. Owns authentication, tenant routing,
GitHub App integration, webhooks, and the license/RBAC surface. Scans are
proxied to `Zyloch-GHAPP-Backend`; the browser never talks to GHAPP directly.

## Run locally

```bash
npm install
cp .env.example .env   # fill in the required values
npm start
npm test               # node:test, no DB required
```

Environment variables are documented inline in `.env.example`.

## Request pipeline

Every protected route composes the same middleware in this order:

| Order | Middleware | Responsibility | Failure |
|-------|-----------|----------------|---------|
| 1 | `middleware/auth` | Verify JWT cookie, load tenant models, set `req.user`, `req.tenant`, `req.license` | 401 |
| 2 | `middleware/tenantGuard` | Require `req.tenant.id` | 403 |
| 3 | `middleware/requireCapability` | Role → capability check (`services/rbac.js`) | 403 |
| 4 | `middleware/requireEntitlement` | Plan feature / scanner / limit check | 403 |
| 5 | Controller | Asserts `tenantId` on every tenant-data query | 403 / 404 |

## RBAC model

Role-only: a tenant user is `admin` or `member`, and `admin` is a strict superset
of `member`. There is no per-user permission store — see
[ADR-001](../docs/multi-tenant/ADR-001-rbac-role-only.md).

Route authorization is expressed as named **capabilities** in
`services/rbac.js`, enforced by `requireCapability(capability)`, and exposed to
the frontend at `GET /api/organization/capabilities` so UI gates match backend
guards exactly.

### Capabilities

| Capability | admin | member |
|------------|:-----:|:------:|
| `organization.read` | ✅ | ✅ |
| `organization.settings.write` | ✅ | ❌ |
| `organization.oauth.write` | ✅ | ❌ |
| `members.read` | ✅ | ✅ |
| `members.manage` | ✅ | ❌ |
| `license.read` | ✅ | ✅ |
| `installations.read` | ✅ | ✅ |
| `repositories.read` | ✅ | ✅ |
| `repositories.delete` | ✅ | ❌ |
| `scans.read` | ✅ | ✅ |
| `scans.trigger` | ✅ | ✅ |
| `summary.refresh` | ✅ | ✅ |

### Route matrix

All rows below run `auth` + `tenantGuard` first unless marked public.
"Capability" blank means authenticated tenant access with no extra role check.

#### `/auth`

| Method | Path | Capability | Notes |
|--------|------|-----------|-------|
| GET | `/auth/github` · `/auth/github/callback` | — | Public OAuth |
| GET | `/auth/google` · `/auth/google/callback` | — | Public, requires `orgId` |
| GET | `/auth/microsoft` · `/auth/microsoft/callback` | — | Public, requires `orgId` |
| POST | `/auth/logout` | — | Public |
| GET | `/auth/check-auth` | — | Public |
| GET | `/auth/me` · `/auth/identities` · `/auth/preferences` · `/auth/organizations` | — | Any authenticated user |
| PUT | `/auth/preferences` | — | Self-service, member allowed |
| POST | `/auth/identities/unlink` | — | Self-service, member allowed |
| POST | `/auth/switch-organization` | — | Re-issues JWT for another tenant the user belongs to |

#### `/api/organization`

| Method | Path | Capability |
|--------|------|-----------|
| GET | `/:orgId/providers` | — (public: enabled login providers) |
| GET | `/` | `organization.read` |
| GET | `/capabilities` | `organization.read` |
| GET | `/license` | `license.read` |
| GET | `/members` | `members.read` |
| POST | `/members/invite` | **`members.manage`** |
| POST | `/members/:userId/deactivate` | **`members.manage`** |
| POST | `/members/:userId/reactivate` | **`members.manage`** |
| PUT | `/oauth/google` · `/oauth/microsoft` | **`organization.oauth.write`** |
| DELETE | `/oauth/google` · `/oauth/microsoft` | **`organization.oauth.write`** |
| GET | `/scans` | `organization.read` |
| PUT | `/scans` | **`organization.settings.write`** |
| GET | `/policies` | `organization.read` |
| PUT | `/policies` | **`organization.settings.write`** |

#### `/api` (GitHub installations)

| Method | Path | Capability |
|--------|------|-----------|
| GET | `/installations` | `installations.read` |
| GET | `/installations/check-status` | `installations.read` |
| GET | `/installations/:installationId/repos` | `repositories.read` |
| GET | `/installations/:installationId/repos/:owner/:repo/branches` | `repositories.read` |
| GET | `/installations/:installationId/repos/:owner/:repo/contents` | `repositories.read` |
| GET | `/installations/:installationId/repos/:owner/:repo/file` | `repositories.read` |

#### `/api/repositories`

| Method | Path | Capability |
|--------|------|-----------|
| GET | `/:installationId` | `repositories.read` |
| GET | `/:installationId/:repositoryName/branches` | `repositories.read` |
| DELETE | `/:installationId/:repositoryName` | **`repositories.delete`** |

#### `/api/installation-summary`

| Method | Path | Capability |
|--------|------|-----------|
| POST | `/:installationId/start` | `summary.refresh` |
| POST | `/:installationId/refresh` | `summary.refresh` |
| POST | `/retry/:jobId` | `summary.refresh` |
| GET | `/status/:jobId` | `summary.refresh` |

#### `/api/scans`

| Method | Path | Capability | Notes |
|--------|------|-----------|-------|
| POST | `/` | `scans.trigger` | Also enforces monthly scan limit |
| GET | `/` · `/latest` · `/:scanId` | `scans.read` | Filtered by `tenantId` |

#### `/webhook`

| Method | Path | Auth |
|--------|------|------|
| POST | `/webhook/github` | GitHub HMAC signature (`verifyWebhook`), no user session |

### Admin bypass

There is no bypass branch in the code. `admin` passes every capability because
each capability lists `admin` among its allowed roles — the guard runs the same
lookup for both roles. Explicitly:

- **Admin does not bypass tenant isolation.** Cross-tenant access is 403/404 for
  every role; ownership is asserted via `installation_index` / `tenantId` filters.
- **Admin does not bypass license entitlements or plan limits.** `requireEntitlement`
  and `licenseLimits` run independently of role.
- **Platform/support powers are not a Zyloch role.** Transferring an installation
  between tenants and editing licenses live in the separate `zyloch-platform-console`
  service behind its own platform auth.

### Adding a route

1. Add or reuse a capability in `services/rbac.js`.
2. Wire `requireCapability('<capability>')` on the route (after `tenantGuard`).
3. Add the row to the matrix above.
4. Gate the corresponding UI control on the capability returned by
   `GET /api/organization/capabilities`.

## Related docs

- [ADR-001 — role-only RBAC](../docs/multi-tenant/ADR-001-rbac-role-only.md)
- [Strategy C implementation plan](../docs/multi-tenant/STRATEGY_C_IMPLEMENTATION_PLAN.md)
- [Tenant contract](../docs/multi-tenant/TENANT_CONTRACT.md)
- [Webhook tenant linking](../docs/multi-tenant/WEBHOOK_TENANT_LINKING.md)
