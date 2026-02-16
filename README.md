# TEZOS4EUDIW : 

TEZOS4EUDIW is a web application that allows users to prove ownership
of a crypto wallet and receive a verifiable credential representing that
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

The issued credential can then be used as a trusted proof that the user
controls a specific crypto address.

## Key capabilities

- Proof of crypto wallet ownership without transactions
- Issuance of SD-JWT Verifiable Credentials
- OIDC4VCI compliant credential issuer
- Integration with Tezos wallets via Beacon
- Delivery of credentials to EUDI wallets
- Real-time issuance status via server-sent events (SSE)

## Supported wallets

### Crypto Wallet

Any Tezos wallet compatible with Beacon, including:

- Temple Wallet
- Kukai Wallet
- Altme Wallet
- Ledger (via supported wallets)

### EUDI Walet

- [Talao](https://www.talao.io/talao-wallet/)
- [Altme](https://www.altme.io/)
- [Igrant.io](https://www.igrant.io/)

## Supported credentials

The issuer can deliver credentials such as:

- Crypto Account Proof (Tezos wallet ownership)

## Standards used

- OpenID for Verifiable Credential Issuance (OIDC4VCI) 1.0
- SD-JWT Verifiable Credentials
- Beacon SDK (Tezos wallet connection)

## Purpose

TEZOS4EUDIW enables trusted linking between a decentralized identity
wallet and a crypto wallet address, allowing verifiable credentials to
be issued and used in identity-based workflows.
