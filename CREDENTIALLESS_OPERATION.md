# GhostCorp Credentialless Routine Operation Standard

Status: architecture requirement; implementation and provider verification pending.

## Goal

The owner must not have to repeatedly provide passwords, API keys, one-time codes, or routine login sessions for GhostCorp to continue operating. "Credentialless" means no repeated owner interaction during normal operation; it does not mean bypassing authentication, account ownership, provider controls, or consent.

## Operating model

1. **One-time owner authorization.** Connect each required provider through its official OAuth or delegated authorization flow where supported. Request the narrowest scopes needed. The owner completes identity checks and grants consent directly with the provider.
2. **Dedicated service identities.** Use separate GhostCorp service accounts, app installations, workload identities, or scoped machine credentials for background work. Do not make a personal interactive login the runtime's identity.
3. **Server-side secret custody.** Store refresh tokens, API credentials, signing keys, and encryption keys only in a managed secret store or protected server environment. Never put secrets in Git, public website code, browser storage, VR clients, logs, analytics, or client downloads.
4. **Automatic token lifecycle.** Refresh tokens before expiry when supported; rotate credentials using provider-supported mechanisms; monitor expiry and revocation; retry transient failures safely. Never attempt to defeat MFA, CAPTCHA, device checks, reauthentication, or provider risk controls.
5. **Durable runtime identity.** Jarvis workers authenticate as service identities and resume after restarts without asking the owner to sign in again, provided the provider's authorization remains valid.
6. **Least privilege and isolation.** Use separate credentials per service and environment. Scope access by action and resource. Public visitors and VR clients never receive backend credentials. Revoke unused credentials.
7. **Owner action only at genuine gates.** Escalate only when the provider requires owner identity verification, a fresh consent grant, a new legal agreement, payment authorization, recovery from revoked access, or a sensitive account/security change. Prepare everything else first and request the smallest possible action.
8. **Graceful degraded mode.** If a token expires, is revoked, or a provider is unavailable, pause only dependent actions, preserve queued work and state, continue independent missions, record the exact blocker, and notify the owner through an authorized channel. Never fabricate a successful connection.
9. **No secret collection in chat.** Never ask the owner to paste passwords, MFA codes, recovery codes, private keys, or long-lived tokens into ChatGPT, Jarvis chat, a repository, or a VR panel. Use official provider authorization screens or secure secret-entry mechanisms.
10. **Audit and recovery.** Record credential metadata (provider, scopes, expiry, last refresh, status, owner-grant reference) without recording secret values. Support revocation, rotation, backup/recovery of non-exportable credentials where providers permit, and tested restart behavior.

## Acceptance tests

- Restart Jarvis workers and verify service authentication resumes without interactive owner login.
- Disconnect the VR headset and verify server-side tasks continue.
- Let a short-lived access token expire and verify supported refresh occurs without user action.
- Revoke a test grant and verify dependent actions pause safely while independent work continues.
- Confirm no secret appears in Git history, browser bundles, VR package, logs, or public endpoints.
- Verify the owner can revoke a provider connection and that access stops promptly.
- Verify all provider-specific identity, consent, MFA, and payment gates remain respected.

## Honest limitations

This standard does not itself create provider connections, issue service credentials, provision secret storage, or guarantee that every provider supports long-lived delegated access. Some providers require periodic reauthentication or human security challenges. Free hosting may also sleep or stop. Each integration must be tested and its real status recorded before it is called active or verified.

The pre-revenue external spending cap remains $0. Do not introduce paid secret managers, hosting, APIs, or services without explicit budget authorization.
