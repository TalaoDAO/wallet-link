# Crypto for EUDI wallet

Updated the 18th of March 2026.

This is a web application that allows users to prove ownership
of a crypto wallet and receive a verifiable attestation (EAA) representing that
ownership in their EUDI wallet.

The application enables the issuance of a Proof of Crypto Ownership
credential bound to a crypto wallet address, using the OpenID for
Verifiable Credential Issuance (OIDC4VCI) standard.

## Overview

This application is part of a broader architecture enabling **secure and compliant crypto-asset payments in Europe using the EUDI Wallet**.

In this context, the application acts as a **credential issuer** responsible for delivering a **Proof of Crypto Account Ownership credential**, also referred to as **SCA (Strong Customer Authentication)**.

### Context

In EUDI-based payment flows, identity, authentication, and transaction execution are separated:

- The **EUDI Wallet** provides identity, authentication, and user consent
- The **crypto wallet** executes the blockchain transaction (self-custodial)
- The **blockchain** acts as the settlement layer
- A **payment gateway** orchestrates the interaction

To securely authorize a payment, the user must prove that they control the blockchain account used for the transaction.

This proof is provided through a **verifiable credential issued by this application**.

### Role of this application

This application enables the issuance of a **Proof of Crypto Account Ownership credential** that:

- Cryptographically links a user to a blockchain address
- Is issued as a **(Qualified) Electronic Attestation of Attributes (Q)EAA**
- Can be presented by the user through their **EUDI Wallet**
- Is used as part of **Strong Customer Authentication (SCA)** in payment flows


### How it is used

Once issued, this credential can be used in EUDI-based payment flows to:

- Prove control of the blockchain account used for payment
- Enable **Strong Customer Authentication (SCA)** aligned with ARF TS12
- Bind user consent to a specific transaction
- Support **identity-based crypto-asset payments**

This enables a model where:

- The user keeps full control of their funds (self-custodial wallet)
- Identity and consent are handled by the **EUDI Wallet**
- Payments are executed directly on the blockchain
- No intermediary controls user assets

### Position in the overall architecture

This application corresponds to the **credential issuance layer** in the broader system:


## What it does

It provides the following functionality:

- Connects to a user's crypto wallet using WalletConnect or Beacon (Tezos)
- Requests the user to sign a message to prove control of their wallet
  address
- Verifies the signature server-side
- Issues a verifiable credential attesting wallet ownership
- Delivers the credential to the user's EUDI wallet via QR code
- Notifies the web application when credential issuance is complete

The issued attestation can then be used as a trusted proof that the user
controls a specific crypto address.

## Key capabilities

- Proof of crypto wallet ownership without transactions
- Issuance of EAA in SD-JWT VC forrmat
- OIDC4VCI compliant credential issuer
- Integration with Tezos wallets via Beacon
- Delivery of attestations to EUDI wallets

## Supported wallets

### Tezos Mobile Crypto Wallet

Any Tezos mobile wallet compatible with Beacon, including:

- [Altme Wallet](https://www.altme.io/)
- [Kukai Wallet](https://wallet.kukai.app/)
- [Temple Wallet](https://www.templewallet.com/#download)
- [Umami](https://www.umamiwallet.com/)


### EVM Mobile Crypto Wallet

Any EVM mobile wallet compatible with WalletConnect, including:

- [Altme Wallet](https://www.altme.io/)
- [Coinbase Wallet](https://www.coinbase.com/)
- [Metamask](https://metamask.io/download)
- [Trust Wallet](https://trustwallet.com/)

### EUDI Wallet compliant wallet with OIDC4VCI draft 15 to Final 1.0

- 🇫🇷 [Altme Wallet](https://www.altme.io/)
- 🇸🇪 [Igrant.io Wallet](https://www.igrant.io/)
- 🇩🇪 [Lissi Wallet](https://www.lissi.id/)
- 🇫🇷 [Talao Wallet](https://www.talao.io/talao-wallet/)
- 🇪🇸 [VID Wallet](https://www.validatedid.com/en/identity/vidwallet)


## Supported credentials

The issuer can deliver credentials such as SD-JWT VC:

- Crypto Account Proof (crypto wallet ownership)

## Standards used

- OpenID for Verifiable Credential Issuance (OIDC4VCI) 1.0
- SD-JWT Verifiable Credentials
- WalletConnect
- Beacon SDK (Tezos wallet connection)

## Purpose

It enables trusted linking between a decentralized identity
wallet and a crypto wallet address, allowing verifiable credentials to
be issued and used in identity-based workflows.

contact@talao.io
