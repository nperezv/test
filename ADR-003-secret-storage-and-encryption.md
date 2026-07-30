# ADR-003 — Secret storage and encryption

**Status:** Proposed
**Date:** 2026-07-30
**Deciders:** Nelson Perez
**Related:** ADR-001 (identity model), ADR-002 (retirement of CorexTerm and VS Corex)
**Supersedes:** the single-blob Master Password vault of COREX Desktop

---

## Context

COREX Desktop stores everything in one AES-256-GCM blob unlocked by a Master Password typed at startup, held only in memory. That model cannot move to a server for two independent reasons:

1. **No human is present at boot.** The systemd unit starts unattended.
2. **Autonomous work has no session.** The Icinga detection poller, the Teams publisher and scheduled reports must run at 03:00 with no one logged in. Any scheme that binds decryption to an interactive session cannot serve them.

Binding the encryption key to MFA was considered and rejected on technical grounds: a TOTP code is a rotating six-digit value the server *verifies*, not stable key material, and an OIDC token is an ephemeral authentication proof. Neither can decrypt data encrypted yesterday. The one genuine exception is the **WebAuthn PRF extension**, which can derive a stable per-credential secret from a passkey or hardware key — but it requires passkeys in Keycloak, is Chromium-only in practice, and makes user tokens unrecoverable if the authenticator is lost. It is deferred, not dismissed.

ADR-002 removed SSH private keys from scope. The material to protect is now exclusively **rotatable API tokens**, which is what makes the trade-offs below acceptable.

---

## Decision

### 1. Envelope encryption

Each secret is encrypted with its own randomly generated **DEK** (AES-256-GCM). The DEK is stored alongside, wrapped by a **KEK**. Application code never handles the KEK — it calls `wrap(dek)` / `unwrap(wrappedDek)` on a **key provider interface**.

This is the decision that matters: it makes the source of the KEK a swappable implementation detail, so the platform can be built before the availability of a corporate KMS is known.

### 2. Schema

```sql
secrets (
  id              uuid primary key,
  owner_type      text not null,        -- 'platform' | 'user'
  owner_id        uuid,                 -- null when owner_type = 'platform'
  purpose         text not null,        -- 'jira' | 'awx' | 'github' | 'icinga' | 'smtp' | 'teams'
  ciphertext      bytea not null,
  iv              bytea not null,
  auth_tag        bytea not null,
  wrapped_dek     bytea not null,
  key_id          text not null,        -- which KEK wrapped this DEK
  wrapping_scheme text not null,        -- 'platform-v1'; later 'webauthn-prf-v1'
  expires_at      timestamptz,
  created_at      timestamptz not null,
  last_used_at    timestamptz
)
```

`key_id` and `wrapping_scheme` ship from day one even though only one value exists. They are what allow a second scheme to be introduced later as a row-by-row migration rather than a redesign.

### 3. Crypto in the application, not in the database

Encryption uses Node's `crypto` (AES-256-GCM). **`pgcrypto` is not used**: it requires passing the key as a SQL parameter, which exposes it in Postgres logs and `pg_stat_activity`. Postgres stores opaque bytes and nothing else.

### 4. KEK provider

- **Default:** injected by systemd via `LoadCredential=`. Never in `.env`, never in the repository, unit file mode 600.
- **If a corporate Vault or KMS is available:** it replaces the provider. No data migration is required beyond re-wrapping DEKs (32 bytes each) — secrets are never re-encrypted.

At boot the service loads the KEK and validates it against a sentinel secret. On failure it **refuses to start**. There is no degraded mode and no fallback to plaintext.

### 5. Rotation

Rotating the KEK re-wraps DEKs only. Secrets are never re-encrypted. This keeps rotation cheap, which is what makes it actually happen.

### 6. Scope in phase 1

All secrets are `platform`-wrapped, including the per-user delegated tokens from ADR-001. Session-bound or per-user key derivation is **not** implemented. The schema supports it; it is enabled when a threat justifies it.

### 7. Secrets never return to the browser

Under any circumstance — not masked, not partially, not for editing, not once. The API exposes presence, purpose, scope and expiry only. Updating a secret means supplying a new value, never reading the old one.

Consequences for the UI, both of which are sanctioned exceptions to the frontend-freeze principle and must be recorded in the master document:

- The Master Password gate (`renderVaultGate`) is removed; Keycloak login replaces it.
- Reveal and copy actions (`creds:reveal`, `toggleRevealCred`, `copyCredSecret`) are removed. The Vault view keeps its visual design but shows presence, scope and expiry.

### 8. The generic credential manager is retired

COREX Desktop allows storing arbitrary `{name, username, url, secret, notes}` entries. This makes COREX a password manager — a responsibility the platform should not take on, and one that grows the moment someone stores a critical service password there. The secret store holds **integration credentials only**, with known schema and known purpose. Corporate password management stays where it belongs.

### 9. Retirement of the Master Password

The Master Password performed three jobs that cannot stay together on a server. Each is replaced independently:

| COREX Desktop | COREX Lab |
|---|---|
| Gate before the UI renders (`renderVaultGate`, `checkVaultGate`, `submitVaultUnlock`) | Keycloak login (OIDC over LDAP/AD) |
| Derives the encryption key (PBKDF2-SHA256, 200k) | KEK provider — systemd `LoadCredential` or KMS (§4) |
| Idle auto-lock (`autoLockMinutes`, `setupAutoLock`) | OIDC session expiry plus frontend inactivity timeout → logout |
| Lock on OS suspend (`setupPowerLock`, `corex:force-lock`) | Not applicable — the server does not suspend |
| Manual lock (`lockVaultNow`, `vault:lock`) | Logout |
| Change Master Password (`vault:changePassword`) | Removed. Credentials live in Active Directory |
| `vault:exists`, `vault:isUnlocked`, `vault:stats` | Session status plus secret-store health endpoint |
| "If forgotten, unrecoverable" | AD password reset. Secrets do not depend on it |

No COREX-specific password exists in COREX Lab.

### 10. Lifecycle gaps closed by this ADR

**Migration off the laptops.** Each engineer holds a local vault containing automation templates, Icinga views, sessions and tokens. A one-off `corex export` command in the frozen desktop application prompts for the Master Password and emits a JSON document **excluding secrets**; COREX Lab provides the corresponding importer. Tokens are deliberately not exported — they are re-entered once in COREX Lab, which is also the natural moment to rotate them. Without this, migration stalls on day one because nobody will re-key their configuration by hand.

**KEK backup and break-glass.** The KEK must **not** be backed up alongside the database — that would make the encryption meaningless, since one stolen backup would contain both halves. It must equally not go unbacked-up, or a lost host means permanently unrecoverable secrets. It is therefore backed up **separately**, in the corporate secret manager or as sealed physical media, with a written restore procedure that is **executed once on a clean VM before production**. A restore procedure that has never been run is an assumption, not a control.

**Bootstrap ordering.** The `svc-corex-lab` token is itself encrypted in the database, which cannot be read before the service starts. Order: systemd injects the KEK → the service validates it against the sentinel → platform secrets are seeded once via an administrative command (`corex secrets set --platform awx`). Never through the web interface, never from a configuration file.

**Offboarding.** Revoking a user in Keycloak must delete their delegated secrets, not merely disable login. This is an explicit deletion step in the user lifecycle, not a side effect.

**Coexistence.** While COREX Desktop remains as a frozen SSH/SFTP client it keeps its own Master Password, because SSH private keys remain on the engineer's machine — which is where they belong (ADR-002). Two different login experiences will therefore coexist during the transition. This is correct behaviour and should be communicated in advance so it is not reported as a defect.

---

## Consequences

**What this protects against.** Database dumps, stolen backups, misdirected replicas, and a DBA with SQL access but no host access. These are the common, realistic breach paths for an internal platform.

**What it does not protect against, stated plainly.** If the host is compromised, the attacker has the KEK — because the server must be able to decrypt unattended, and that is a requirement, not an oversight. The desktop Master Password model protected against more, but it cannot serve autonomous work. This is a conscious trade-off and is recorded here so it is never mistaken for an omission. Host hardening, least-privilege service accounts and audit logging carry the weight that encryption cannot.

**Cost.** Key lifecycle, rotation procedure, sentinel validation and a documented recovery path. Modest, and mostly one-time.

**Deferred.** WebAuthn PRF wrapping for user-delegated tokens (`wrapping_scheme = 'webauthn-prf-v1'`). Revisit criteria: passkeys deployed in Keycloak, and a threat model that justifies protecting the tokens of users who are not currently logged in. Note the accepted consequence — losing the authenticator means the user re-enters their tokens, which is acceptable precisely because ADR-002 limited the stored material to rotatable API tokens.
