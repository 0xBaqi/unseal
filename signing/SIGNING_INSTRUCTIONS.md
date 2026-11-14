# Signing Instructions — Unseal Gate A.2 Proof

This document explains how to sign a NEP-413 challenge with a real NEAR testnet wallet and submit the result to the backend verifier.

> **Security reminder**: Never share your seed phrase or private key. These instructions only require your wallet's signing UI.

---

## Prerequisites

- A NEAR testnet account (e.g. `yourname.testnet`)
- One of the following wallets connected to **testnet**:
  - [Meteor Wallet](https://wallet.meteorwallet.app) ← recommended
  - [MyNearWallet](https://testnet.mynearwallet.com) (redirect flow)
  - [HERE Wallet](https://herewallet.app) (mobile)
- The backend server running: `npm run serve` (listening on `http://localhost:3000`)

---

## Step 1 — Get a Challenge from the Server

```bash
curl -s -X POST http://localhost:3000/challenge \
  -H "Content-Type: application/json" \
  -d '{"accountId": "YOUR_ACCOUNT.testnet"}' | jq .
```

**Expected response:**
```json
{
  "nonceB64": "BASE64_NONCE",
  "message": "Sign in to Unseal Gate A.2 proof",
  "recipient": "unseal-gate-a.proof",
  "accountId": "YOUR_ACCOUNT.testnet",
  "expiresAt": 1700000300000,
  "ttlSeconds": 300
}
```

Save the `nonceB64` value. The challenge expires in 5 minutes.

---

## Step 2 — Sign the Challenge with Your Wallet

You need to call `wallet.signMessage()` with the **exact** values from the challenge response.

### Option A — Using Meteor Wallet (Browser Extension)

Open your browser DevTools console on any page connected to testnet via Meteor Wallet Selector.

```javascript
// Paste in browser console (DevTools)
const selector = window.selector; // or however your dApp exposes it
const wallet = await selector.wallet('meteor-wallet');

const response = await wallet.signMessage({
  message: 'Sign in to Unseal Gate A.2 proof',
  recipient: 'unseal-gate-a.proof',
  nonce: new Uint8Array(Buffer.from('PASTE_NONCE_B64_HERE', 'base64')),
});

console.log('accountId:', response.accountId);
console.log('publicKey:', response.publicKey);
console.log('signature:', response.signature); // base64 string
```

Copy the three values: `accountId`, `publicKey`, `signature`.

### Option B — Using the near-api-js signing script (isolated key-pair test)

> ⚠️ For automated or headless cryptographic tests only.
> Pass credentials via environment variables; never commit or hardcode keys.

```bash
NEAR_ACCOUNT_ID="YOUR_ACCOUNT.testnet" \
NEAR_SECRET_KEY="ed25519:YOUR_PRIVATE_KEY" \
node signing/sign_challenge.js
```

The script uses `near-api-js` `KeyPairSigner.fromSecretKey()`, requests a challenge from `/challenge`, signs it, submits to `/verify`, and outputs the verification results.

---

## Step 3 — Submit the Signed Response to the Verifier

```bash
curl -s -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{
    "accountId": "YOUR_ACCOUNT.testnet",
    "publicKey": "ed25519:YOUR_PUBLIC_KEY",
    "signatureB64": "BASE64_SIGNATURE",
    "nonceB64": "PASTE_NONCE_B64_HERE"
  }' | jq .
```

**Expected success response (200):**
```json
{ "ok": true, "accountId": "YOUR_ACCOUNT.testnet", "publicKey": "ed25519:..." }
```

---

## Step 4 — Run the Real-Wallet Integration Test

Export the values as environment variables and run the RPC test suite:

```bash
export NEAR_ACCOUNT_ID="YOUR_ACCOUNT.testnet"
export NEAR_PUBLIC_KEY="ed25519:YOUR_PUBLIC_KEY"
export NEAR_SIGNATURE_B64="BASE64_SIGNATURE"
export NEAR_NONCE_B64="PASTE_NONCE_B64_HERE"
export NEAR_MESSAGE="Sign in to Unseal Gate A.2 proof"

REAL_SIG=1 npm run test:rpc
```

---

## What Gets Verified

When you submit the response, the backend:

1. **Validates the nonce** — it was issued by this server, is not expired, and has not been used before
2. **Checks recipient binding** — `recipient` in the signed payload must equal `unseal-gate-a.proof`
3. **Retrieves your keys from testnet RPC** — calls `view_access_key` to confirm the stated public key is registered on your account with FullAccess permission
4. **Verifies the Ed25519 signature** — the signed payload (Borsh-serialized message+nonce+recipient with NEP-413 tag, SHA-256 hashed) must match the signature using the stated public key

All four checks must pass. The backend fails closed on any error.

---

## Security Properties Being Demonstrated

| Property | Test |
|----------|------|
| Valid signature passes | Real wallet → server |
| Tampered message rejected | `REAL_SIG=1 npm run test:rpc` |
| Wrong recipient rejected | Automatic in verifier |
| Replay (nonce reuse) rejected | Unit test + try submitting twice |
| Expired challenge rejected | Unit test |
| Key not on-chain rejected | Unit test + RPC integration test |
| RPC failure → fail closed | Unit test + bad-endpoint RPC test |
| Non-FullAccess key rejected | Unit test |

---

## Notes on Labeling

All tests that run without a real wallet are labeled `[SIMULATED]`.
All tests hitting the real NEAR testnet RPC are labeled `[REAL-RPC]`.
Tests requiring a live wallet signature are labeled `[REQUIRES-REAL-WALLET]`.

No model assertion is accepted as evidence of real wallet signing.
