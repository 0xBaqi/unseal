# Unseal — Live Product Demo & On-Chain Verification Evidence

This document captures verified, on-chain execution evidence from the deployed Unseal application on **NEAR Testnet**.

- **Live Application URL**: [https://unseal.baronal.xyz](https://unseal.baronal.xyz)
- **NFT Access Pass Contract**: [`unseal-nft-55335700.testnet`](https://testnet.nearblocks.io/address/unseal-nft-55335700.testnet)
- **Primary Pass (Alpha Space)**: `pass-alpha-1` (Owner: `baronal.testnet`)
- **Transferable Pass**: `pass-transfer-493545`

---

## 1. Demonstrated Core Workflows

### Flow 1: Disconnected Holder Experience & Metadata Protection
1. Visitor navigates to `https://unseal.baronal.xyz`.
2. The Holder View displays the **Confidential Vault Overview**:
   - Only the **Public Demo Space** (`space-alpha`) with synthetic sample metadata is discoverable.
   - Private user spaces and confidential document titles are shielded from unauthenticated visitors.
   - Live on-chain status prompts the user to connect a wallet: `🔒 Connect wallet to check pass ownership`.
   - The document unlock button is strictly disabled.

### Flow 2: Multi-Wallet Selection & NEP-413 Authentication
1. User clicks **⚡ Connect Wallet**.
2. The **Wallet Selector Modal** opens with detected NEAR options:
   - **Meteor Wallet** (Recommended & verified)
   - **HOT Wallet**
   - **Sender Wallet**
   - **Nightly Wallet**
   - **Manual Account (Judge Test Mode)** (for testing without extensions)
3. Upon selecting an account (e.g. `baronal.testnet`), the application queries NEAR Testnet RPC view method `nft_token` at `finality: 'final'`.
4. The on-chain badge confirms:
   `✓ On-Chain Verified: Your account (baronal.testnet) owns pass "pass-alpha-1"! Ready to unlock.`

### Flow 3: Gasless Document Unlock & Ephemeral Viewer
1. User clicks **🔓 Authenticate & Unlock Private Document**.
2. Server issues a cryptographically secure 32-byte nonce challenge (`POST /challenge`).
3. User signs the NEP-413 off-chain challenge in their wallet with zero transaction fees.
4. Server verifies the Ed25519 signature and on-chain `FullAccess` key.
5. Private document is streamed from Cloudflare R2 into an ephemeral in-memory `Blob` iframe with `Cache-Control: private, no-store`.

---

## 2. Live On-Chain Revocation Evidence (NEAR Testnet)

During verification, real on-chain access pass minting, transfer, and immediate revocation were verified on the live NEAR testnet contract `unseal-nft-55335700.testnet`:

```text
[L5 Step 0] Minting fresh access pass "pass-transfer-429407" to Bob: bob-55400334.testnet...
[L5 Step 1] Verifying initial access for Bob: bob-55400334.testnet...
[L5 Step 1 Result] Bob initial access GRANTED (200 OK)
[L5 Step 2] Creating recipient subaccount on-chain: c0321.bob-55400334.testnet...
[L5 Step 2 Result] Recipient account created on-chain: c0321.bob-55400334.testnet
[L5 Step 3] Bob executing real on-chain nft_transfer to c0321.bob-55400334.testnet...
[L5 Step 3 Result] Real nft_transfer confirmed!
Transaction Hash: 5tdfzAGf6pyoEn8E3xvEdrv4SWyTVVyX5yNP1XgHxgxm
Explorer Link: https://testnet.nearblocks.io/txns/5tdfzAGf6pyoEn8E3xvEdrv4SWyTVVyX5yNP1XgHxgxm

[L5 Step 4] On-chain token owner verified as: c0321.bob-55400334.testnet
[L5 Step 5] Querying space access for previous owner Bob (expect 403)...
[L5 Step 5 Result] Previous owner Bob IMMEDIATELY REVOKED (403 NOT_TOKEN_OWNER)
[L5 Step 6] Querying space access for new owner Charlie (expect 200 OK)...
[L5 Step 6 Result] New owner Charlie GRANTED ACCESS (200 OK)
```

**Key Security Takeaway**: Revocation occurs at block finality with zero stale-session delay. Once the `nft_transfer` finalized on NEAR testnet, Bob was immediately denied access on his next request without requiring cache purging or database invalidation.
