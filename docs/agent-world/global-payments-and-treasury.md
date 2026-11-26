# Global Payments, Wallets, and Treasury Operations

## Product requirement

GhostCorp should operate routine, provider-authorized payment and treasury workflows with minimal owner involvement after onboarding. The owner should not be the manual operator for each invoice, payment, refund, reconciliation, supplier payment, or routine business payout.

This is an automation target, not a promise that every country, payment rail, wallet, or provider is universally available. Availability depends on the legal entity, jurisdiction, provider underwriting, supported currencies, account status, and transaction type.

## Operating model

1. A customer selects a product or service and pays through a locally appropriate, provider-supported checkout method.
2. The payment orchestrator selects an eligible payment provider and method based on customer country, merchant entity, currency, risk, fees, settlement speed, and availability.
3. The provider processes the payment. GhostCorp trusts provider-confirmed webhooks/API state, not screenshots, customer claims, or an agent's inference.
4. A double-entry ledger records gross amount, currency, fees, tax components where known, refunds, chargebacks, reserves, settlement status, and net proceeds.
5. A treasury policy allocates cleared funds among tax/reserve obligations, business operating treasury, product/business sub-ledgers, and owner-distribution payable.
6. Payouts are initiated through provider-supported payout APIs to previously verified, authorized destinations, within configured limits and schedules.
7. Reconciliation compares internal ledger entries against provider balance transactions, settlement reports, bank/wallet statements where supported, and payout confirmations.
8. The owner receives concise exception alerts and periodic reporting, not routine approval requests for every low-risk, in-policy transaction.

## Payment-method coverage

Build a provider abstraction rather than a single hard-coded processor. Evaluate and integrate providers that legitimately support the relevant merchant entity and countries, including:
- card acquiring and local card schemes;
- bank transfers and open-banking/payment initiation where supported;
- local payment methods and bank redirects;
- supported digital wallets and mobile payment methods;
- recurring billing, invoices, subscriptions, and payment links;
- cryptocurrency acceptance through compliant processors or direct wallet flows where appropriate.

The checkout experience should show only methods actually supported for that customer, merchant, currency, and transaction. Do not claim universal worldwide acceptance.

## Country and currency intelligence

Maintain a versioned jurisdiction/capability registry with:
- country and region codes;
- supported merchant entity and provider combinations;
- presentment and settlement currencies;
- local payment methods;
- payout rails and destination eligibility;
- supported languages, address formats, phone formats, tax identifiers, and invoice requirements;
- KYC/KYB, sanctions-screening, AML, consumer-protection, privacy, record-retention, and reporting requirements;
- restrictions, thresholds, effective dates, source links, and last-verified timestamps.

Use locale-aware templates for invoices, receipts, payment notices, refund notices, customer emails, and required disclosures. Support translated customer communications and local formatting. Do not fabricate tax registrations, legal entities, bank details, addresses, or regulatory approvals.

## Wallet and digital-asset architecture

Use a custody-risk-aware wallet adapter. Distinguish:
- provider-custodied business balances;
- self-hosted wallets controlled by the legal entity;
- segregated per-business or per-purpose wallets;
- customer wallets (never assume a customer has one);
- owner distribution destinations.

For customers who do not have crypto wallets, offer fiat checkout or provider-supported walletless payment options. If crypto conversion is requested, perform it only where the merchant, provider, jurisdiction, asset, and transaction are eligible. Conversion must be explicitly configured in treasury policy, disclose exchange rates/spreads/fees, and record both sides of the conversion. Never imply a fiat payment has been converted until the provider confirms it.

Use institutional/provider-supported custody and key-management controls where possible. For self-custody, require secure key generation, hardware-backed or managed signing, encrypted backups, separation of duties, recovery procedures, transaction simulation, allowlisted destinations, and documented incident response. Never put seed phrases, private keys, API secrets, recovery codes, or signing material in prompts, logs, repository files, or ordinary agent memory. Agents should call narrowly scoped signing services; they should not read raw private keys.

## Autonomous operating authority

After onboarding and explicit policy configuration, agents may autonomously:
- create invoices, payment links, checkout sessions, receipts, and routine customer communications;
- collect and verify payment status from trusted provider APIs/webhooks;
- retry eligible failed payments within customer consent and provider rules;
- issue policy-compliant refunds below configured per-transaction and daily limits;
- reconcile settlements and fees;
- prepare tax/reserve allocations and internal ledger transfers;
- pay approved recurring infrastructure and supplier invoices within vendor allowlists and budgets;
- initiate routine payouts to previously verified destinations within frequency and amount limits;
- manage subscription lifecycle and send dunning/customer service notices;
- flag fraud, disputes, chargebacks, unusual activity, liquidity shortfalls, and reconciliation mismatches;
- produce daily/weekly financial reports and exception queues.

The system must not depend on the owner manually handling each ordinary payment. It must, however, stop and request a human or provider action when a law, provider, bank, exchange, custody policy, or security control requires it.

## Explicitly gated operations

Never bypass or impersonate a human for:
- legal-entity formation, beneficial-owner declarations, KYC/KYB, identity verification, sanctions/AML checks, tax registrations, or regulated licensing;
- acceptance of provider terms, account opening, credential issuance, or authorization requiring the account holder;
- adding/changing owner payout destinations, bank accounts, wallet ownership, signing policies, or recovery contacts;
- raising budgets, changing risk limits, disabling controls, or granting agents new financial permissions;
- high-value, unusual, irreversible, sanctioned, suspicious, or out-of-policy transactions;
- responding to legal process or making regulated financial/tax/legal determinations.

Automate preparation, validation, reminders, document assembly, and status tracking around these steps, but never falsify information or claim the step is complete before verification.

## Treasury structure

Maintain separate, reconcilable books for:
- each operating business or bot-owned business unit;
- parent GhostCorp operating treasury;
- tax and statutory reserves;
- refunds, disputes, and chargeback reserves;
- owner distributions payable;
- restricted or escrowed funds where applicable.

Do not commingle customer funds where segregation is required. Do not treat pending, reversible, held, or unsettled funds as withdrawable earnings. Calculate distributable cash only after provider fees, refunds, chargebacks, reserves, taxes and liabilities, and working-capital policy are accounted for. The owner may designate supported payout destinations during onboarding; agents cannot silently change them.

## Security and governance

- Least-privilege credentials per provider, business, environment, and action.
- Secrets stored only in a managed secret store; rotate and revoke credentials.
- Separate read, payment-create, refund, payout, conversion, and configuration permissions.
- Webhook signature verification, idempotency keys, replay protection, rate limits, and immutable audit records.
- Transaction limits per transaction/day/month, velocity limits, vendor and destination allowlists, and dual-control thresholds.
- Fraud and sanctions screening through appropriate providers.
- An independent policy engine evaluates every money-moving action before execution.
- Agents cannot approve their own exception, modify their own limits, or disable monitoring.
- Emergency pause/kill switch, key revocation, provider circuit breakers, and incident playbooks.
- No live payment credentials or secrets in GitHub, source code, prompts, test fixtures, or logs.

## Free-first and cost controls

Keep the existing pre-revenue paid-API spend cap at $0. Prefer provider free tiers, open standards, local development, and sandbox/test environments. Payment processors may charge transaction fees; disclose and account for them. Do not sign up for paid services, incur subscriptions, or increase spend without an owner-approved budget and provider authorization. Revenue does not automatically authorize unrestricted reinvestment.

## Implementation phases

1. **Ledger and policy core:** typed money/currency values, double-entry ledger, idempotent event ingestion, reconciliation engine, policy decision records, and simulated provider.
2. **Sandbox integrations:** implement provider adapters using test credentials, webhook signature tests, refunds, settlement reports, and payout simulations.
3. **First live merchant rail:** after legal entity and provider onboarding, enable one supported fiat checkout provider and verified payout destination.
4. **International expansion:** add providers and local payment methods country by country using the jurisdiction registry and verified provider capability.
5. **Digital assets:** add compliant fiat-to-crypto conversion and custody adapters only where legally/provider supported; keep keys isolated behind signing services.
6. **Autonomous operations:** gradually enable low-risk routine actions under strict budgets, allowlists, exception alerts, reconciliation, and rollback/compensation workflows.

## Acceptance tests

- A simulated customer payment creates exactly one ledger posting despite duplicate webhook delivery.
- Pending, failed, reversed, disputed, refunded, and settled states are distinct.
- Fees, FX, and conversion spreads are represented explicitly.
- A payout to an unverified or changed destination is rejected.
- A routine in-policy payment/refund/payout can complete without owner intervention once all required onboarding and policy prerequisites are met.
- Out-of-policy or high-risk transactions are blocked and surfaced as actionable exceptions.
- Country/method combinations not verified as supported are not offered at checkout.
- No agent can access raw signing keys or provider secrets.
- Reconciliation detects missing, duplicated, and mismatched provider transactions.
- Existing $0 pre-revenue paid-API cap and all current approval/Action Center controls remain enforced.
