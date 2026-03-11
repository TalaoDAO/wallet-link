# TEZOS4EUDIW 0.1.0

TEZOS4EUDIW is a web application that allows users to prove ownership
of a crypto wallet and receive a verifiable attestation (EAA) representing that
ownership in their EUDI wallet.

The application enables the issuance of a Proof of Crypto Ownership
credential bound to a Tezos wallet address, using the OpenID for
Verifiable Credential Issuance (OIDC4VCI) standard.

## What it does

TEZOS4EUDIW provides the following functionality:

- Connects to a user's Tezos crypto wallet using Beacon
- Requests the user to sign a message to prove control of their wallet
  address
- Verifies the signature server-side
- Issues a verifiable credential attesting wallet ownership
- Delivers the credential to the user's EUDI wallet via QR code
- Notifies the web application when credential issuance is complete

The issued attestation can then be used as a trusted proof that the user
controls a specific Tezos crypto address.

## Key capabilities

- Proof of crypto wallet ownership without transactions
- Issuance of EAA in SD-JWT VC forrmat
- OIDC4VCI compliant credential issuer
- Integration with Tezos wallets via Beacon
- Delivery of attestations to EUDI wallets

## Supported wallets

### Crypto Wallet

Any Tezos wallet compatible with Beacon, including:

- Temple Wallet
- Kukai Wallet
- Altme Wallet
- Ledger (via supported wallets)

### EUDI Wallet compliant with OIDC4VC Final 1.0

- 🇫🇷 [Talao Wallet](https://www.talao.io/talao-wallet/)
- 🇫🇷 [Altme Wallet](https://www.altme.io/)
- 🇸🇪 [Igrant.io Wallet](https://www.igrant.io/)
- 🇪🇸 [VID Wallet](https://www.validatedid.com/en/identity/vidwallet)

## Supported credentials

The issuer can deliver credentials such as SD-JWT VC:

- Crypto Account Proof (Tezos wallet ownership)

## Standards used

- OpenID for Verifiable Credential Issuance (OIDC4VCI) 1.0
- SD-JWT Verifiable Credentials
- Beacon SDK (Tezos wallet connection)

## Purpose

TEZOS4EUDIW enables trusted linking between a decentralized identity
wallet and a crypto wallet address, allowing verifiable credentials to
be issued and used in identity-based workflows.

contact@talao.io
