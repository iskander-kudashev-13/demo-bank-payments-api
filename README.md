# Demo Bank · payments screening API

A synthetic bank's payment screening service, connected to the **Scam Weather** interbank fraud signal network. It is a sandbox for showing how [Devin](https://devin.ai) maintains a bank's integration: when other banks start sending a new type of fraud signal, Devin opens a pull request here that adds support, with tests, and a bank engineer reviews and merges it.

All data is synthetic. This repository does not belong to or describe any real bank.

## What it does

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/signals` | The bank's Scam Weather node pushes a verified, decrypted signal. Returns the ack status: `applied`, `obsolete` or `expired`. |
| `POST /v1/payments/screen` | The payment gateway checks an outgoing payment before money leaves. Returns `APPROVED` or `REVIEW_REQUIRED` with the reason. |
| `GET /v1/signals/unsupported` | Active signals the bank stores but cannot match to payments yet. |

```bash
go test ./...
go run ./cmd/api   # listens on :8081
```

## Signal coverage

The network carries several fraud signal kinds. This bank covers only some of them.

| Kind | Fraud | Indicator | Status |
| --- | --- | --- | --- |
| `bec_beneficiary` | Business email compromise, invoice redirected to a mule account | `account_hmac` (IBAN) | covered |
| `app_scam_beneficiary` | Investment, purchase or romance scam payee | `account_hmac` (IBAN) | covered |
| `mule_account` | Account receiving and forwarding scam proceeds | `account_hmac` (IBAN) | covered |
| `aani_proxy_scam` | Scam payee on an Aani mobile-number alias | `phone_hmac` (E.164 UAE mobile) | covered |
| `crypto_offramp_wallet` | Proceeds cashed out to a crypto wallet via a VASP | `wallet_hmac` | **not covered** |
| `ato_device` | Device seen in confirmed account takeovers | `device_hmac` (payer's mobile banking device fingerprint, `channel.device_id`) | covered |

Uncovered signals are stored and reported in `Decision.unchecked_kinds`, so the fraud desk knows which payments could not be fully checked.

## Layout

```
internal/signals    signal model, IBAN, UAE mobile and device ID normalisation, indicator HMAC
internal/payments   the bank's outgoing payment format and parser
internal/screening  signal store, matching and the bank's policy
cmd/api             HTTP API
testdata            synthetic payments
```

## How Devin works here

1. Another bank sends a signal kind this bank does not cover; the Scam Weather fraud desk shows it in the uncovered alerts log.
2. An analyst presses **Fix with Devin**. Devin gets the signal kind, the banks that sent it and an example, plus this repository.
3. Devin adds the normaliser and indicator, matching, a draft policy rule and tests, runs `go test ./...`, and opens a draft PR.
4. CI runs on the PR. A bank engineer reviews and merges. Fraud Risk approves the policy rule.

Rules for changes: do not weaken existing tests, keep decisions deterministic, use synthetic data only.
