# Unseal — NFT-Gated Confidential Document Vault on NEAR

> **NEAR Protocol Beta Hackathon Submission**  
> Verifiable, zero-gas off-chain authentication via NEP-413 combined with real-time on-chain NEP-171 NFT access gating and private Cloudflare R2 document streaming.

### 🌐 Live Deployment & Contract Links
- **Live Demo Application**: [https://unseal.baronal.xyz](https://unseal.baronal.xyz)
- **Public GitHub Repository**: [https://github.com/0xBaqi/unseal](https://github.com/0xBaqi/unseal)
- **Network**: NEAR Testnet (`https://archival-rpc.testnet.near.org`)
- **NEP-171 NFT Contract**: [`unseal-nft-55335700.testnet`](https://testnet.nearblocks.io/address/unseal-nft-55335700.testnet)
- **Mainnet Payout Account**: `baronal.near`

---

## 1. Overview & Problem Statement

### The Problem
Traditional document sharing (e.g., DocSend, Pitch, Google Drive) relies on centralized access control lists, email magic links, or bearer URLs. These models suffer from critical limitations:
1. **Stale Sessions & Lagged Revocation**: Once a viewer receives access or downloads a link, revocation requires database invalidation that is easily circumvented by cached JWTs or long-lived browser sessions.
2. **Non-Transferable Access**: Enterprise confidentiality, board materials, and private financial audits cannot be legally transferred or assigned as liquid on-chain rights.
3. **Link Leakage**: Shared URLs can be forwarded, indexed, or intercepted.

### The Unseal Solution
Unseal introduces **NFT-Gated Private Document Delivery** with **Zero-Stale-Session Revocation**:
- **Bearer Credential On-Chain**: Document access is bound to cryptographic ownership of a specific NEAR Protocol NEP-171 NFT token (Access Pass).
- **Zero-Gas NEP-413 Cryptographic Authentication**: Viewers authenticate without gas fees or transaction latency by signing a single-use 32-byte server nonce with their NEAR wallet.
- **Revocation at Block Finality**: Document delivery queries NEAR RPC `nft_token` with `finality: 'final'` on **every single request**. When an access pass NFT is transferred or burned on-chain, previous holders are locked out at block finality with zero caching lag.
- **Private Storage & Ephemeral Streaming**: Documents reside in private Cloudflare R2 storage with unguessable UUID keys, streamed directly into an ephemeral in-memory browser Blob that is destroyed when the tab or document viewer is closed.

---

## 2. Technical Architecture & Security Model

```
                               ┌─────────────────────────────────────────────────────────────┐
                               │                    NEAR Blockchain Testnet                  │
                               │                                                             │
                               │   NEP-171 NFT Contract: unseal-nft-55335700.testnet        │
                               │   Token: pass-alpha-1 ───> owner_id: "alice.testnet"        │
                               └──────────────┬──────────────────────────────▲───────────────┘
                                              │                              │
                                    Live RPC Query                            │ On-chain
                                  (finality: 'final')                         │ nft_transfer
                                              │                              │
┌──────────────────────────┐                  ▼                              │
│       Browser User       │        ┌───────────────────┐                    │
│  (Meteor / Multi-Wallet) │        │   Unseal Server   │                    │
│                          │        │   (Node.js + S3)  │                    │
│ 1. Request Challenge     ├───────>│                   │                    │
│ 2. Sign NEP-413 Nonce    │<───────┤ POST /challenge   │                    │
│ 3. Send Signed Proof     ├───────>│ POST /verify      │                    │
│    + Space Access        │        │                   │                    │
│                          │        │ Authorization:    │                    │
│                          │        │ • Valid Nonce?    │                    │
│                          │        │ • Ed25519 OK?     │                    │
│                          │        │ • FullAccess Key? │                    │
│                          │        │ • On-Chain Owner? │                    │
│                          │        └─────────┬─────────┘                    │
│                          │                  │ Access                       │
│                          │                  │ Granted                      │
│                          │                  ▼                              │
│                          │        ┌───────────────────┐                    │
│ 4. Streams Private PDF   │<───────┤   Cloudflare R2   │                    │
│    into In-Memory Blob   │        │   Private Vault   │                    │
│    (Zero-Disk/No-Store)  │        │  (unseal-private) │                    │
│ └──────────────────────────┘        └───────────────────┘                    │
                                                                             │
When Alice transfers pass-alpha-1 to Bob ────────────────────────────────────┘
 • On next request, Alice's ownership check yields 403 NOT_TOKEN_OWNER.
 • Bob's next request yields 200 OK and streams the document.
```

### A. NEP-413 Off-Chain Challenge/Response Authentication
1. **Challenge Issuance** (`POST /challenge`): The backend issues a cryptographically secure 32-byte nonce with a strict 5-minute TTL bound to `recipient: "unseal-gate-a.proof"`.
2. **Wallet Signature**: The user signs the challenge payload (`tag = 2147484061`, `message`, `recipient`, `nonce`) using their NEAR wallet's private key without paying gas.
3. **Server Verification** (`POST /verify`):
   - Nonce existence, expiry, and single-use consumption are verified (preventing replay attacks).
   - Ed25519 signature is verified over SHA-256 of the NEP-413 payload using `@noble/curves/ed25519`.
   - The server queries NEAR testnet RPC at `finality: 'final'` to ensure the public key is an active `FullAccess` key registered to `accountId` on-chain.

### B. Live On-Chain Gating (Zero Caching)
- Access to gated spaces (`POST /space/:id/access` and `POST /space/:id/content`) **never** uses long-lived bearer tokens or cached authorization records.
- On every document request, `verifySpaceAccess` executes a live view call `nft_token` against the contract at `finality: 'final'`.
- The server validates:
  1. Token exists on the target contract.
  2. Current on-chain `token.owner_id === accountId`.
  3. Token expiration timestamp (if configured).
- If the token was transferred or revoked, the server immediately denies access (`403 NOT_TOKEN_OWNER`).

### C. Private Storage & Ephemeral Delivery
- Confidential PDFs are uploaded to private Cloudflare R2 storage (`unseal-private`) using unpredictable UUID paths (`spaces/{spaceId}/{uuid}.pdf`).
- Server validates `%PDF-` magic bytes and enforces a strict 15MB file size limit.
- Streams with HTTP headers:
  - `Cache-Control: private, no-store, no-cache, must-revalidate`
  - `Content-Type: application/pdf`
  - `X-Content-Type-Options: nosniff`
- In the browser, the file is buffered into an in-memory `Blob` and viewed in an embedded iframe. Closing the viewer revokes the object URL and frees memory.

---

## 3. Judge Walkthrough (Using the Live Deployed Application)

Judges can explore and evaluate the application immediately using the live production deployment:

### 🔗 Open: [https://unseal.baronal.xyz](https://unseal.baronal.xyz)

### Step 1: Open the Application & Holder Landing View
- Visit [https://unseal.baronal.xyz](https://unseal.baronal.xyz).
- Notice the **Confidential Vault Overview**: Unauthenticated visitors see only the clearly labelled **Public Demo Space (Synthetic Testnet Vault)**. Real user vaults and confidential document directories are shielded behind wallet authentication.

### Step 2: Connect a Supported NEAR Wallet
- Click the **⚡ Connect Wallet** button in the navigation bar or the hero card.
- The **Wallet Selector Modal** opens, presenting supported NEAR options:
  - **Meteor Wallet** (Recommended & verified for NEP-413 signing and live minting).
  - **HOT Wallet** (Ecosystem connector guidance).
  - **Sender Wallet** (Injected browser extension).
  - **Nightly Wallet** (Injected browser extension).
  - **Manual Account (Judge Test Mode)**: If you do not have a wallet extension installed, select this option to test with any NEAR testnet account (e.g. `baronal.testnet`).
- Once connected, your account ID displays in the header pill.

### Step 3: View Gated Document (Alpha Demo Space)
- On the **Document Vault** tab, select **Unseal Alpha Demo Vault (Synthetic Testnet Space)** (`space-alpha`).
- If connected with `baronal.testnet` (or an account holding `pass-alpha-1`):
  - The live on-chain status confirms: `✓ On-Chain Verified: Your account owns pass "pass-alpha-1"! Ready to unlock.`
  - Click **🔓 Authenticate & Unlock Private Document**.
  - Approve the NEP-413 signature challenge.
  - The confidential sample document streams directly into the embedded viewer.
- If connected with an account that does *not* own `pass-alpha-1`:
  - The UI accurately indicates: `🔒 Access Restricted: Your account does not hold required pass "pass-alpha-1".`

### Step 4: Creator Studio (Registering a Space & Uploading a PDF)
- Switch to the **🛠️ Creator Studio** tab.
- Enter a unique space slug (e.g. `space-audit-judge`) and space name.
- Click **Create Document Space** and sign the NEP-413 creator authorization.
- Select any PDF document (< 15MB) and click **Upload to Private Vault**.
- The server validates magic bytes `%PDF-`, uploads to private storage, and registers the document.

### Step 5: Mint & Transfer Access Passes
- Switch to the **🛡️ Pass & NFT Management** tab.
- Click **Inspect Token** to query any on-chain token ID (e.g. `pass-alpha-1` or `pass-transfer-493545`).
- Enter a recipient account to mint a new pass on `unseal-nft-55335700.testnet`.
- To test live revocation: transfer the pass to another testnet subaccount with **Transfer Pass**.
- Switch back to the Document Vault: the previous owner is immediately denied access on their next request (`403 NOT_TOKEN_OWNER`).

---

## 4. On-Chain Contracts & Testnet Deployment

The NEP-171 NFT contract is actively deployed on NEAR testnet:

| Contract Attribute | Value |
| :--- | :--- |
| **Contract ID** | `unseal-nft-55335700.testnet` |
| **Network** | NEAR Testnet (`https://archival-rpc.testnet.near.org`) |
| **Standard** | NEP-171 (NFT Core), NEP-177 (Metadata), NEP-178 (Approval Management) |
| **Default Alpha Pass** | `pass-alpha-1` (owned by `baronal.testnet`) |
| **Transferable Pass** | `pass-transfer-493545` |
| **Contract Explorer** | [NEARBlocks Explorer](https://testnet.nearblocks.io/address/unseal-nft-55335700.testnet) |

---

## 5. Verification & Automated Test Suite Results

The automated test suite reconciles across 9 distinct test suites:

```text
ℹ tests 64
ℹ suites 9
ℹ pass 60
ℹ fail 0
ℹ cancelled 0
ℹ skipped 4
ℹ todo 0
ℹ duration_ms 57507.85
```

### Test Suite Breakdown

1. **Gate A.3 Live Testnet RPC Ownership & Revocation Tests** (`test/ownership.rpc.test.js`):
   - **6 passed**:
     - `L1 [Positive]`: Live on-chain view call confirms `baronal.testnet` ownership of `pass-alpha-1`.
     - `L2 [Negative]`: Unrelated account is rejected with `403 NOT_TOKEN_OWNER`.
     - `L3 [Negative]`: Query for mismatched token rejected with `403 TOKEN_MISMATCH`.
     - `L4 [Negative]`: Query with mismatched contract ID rejected with `403 CONTRACT_MISMATCH`.
     - `L5 [Live Revocation]`: Real on-chain mint to Bob -> Bob initial access GRANTED -> Bob executes real on-chain `nft_transfer` to Charlie -> Bob immediately REVOKED (403) at block finality -> Charlie immediately GRANTED access (200).
     - `L6 [Negative]`: Fail-closed on RPC failure -> `503 RPC_FAILURE`.
2. **Gate A.3 Ownership & Space Access Unit Tests** (`test/ownership.unit.test.js`):
   - **9 passed**: Valid owner grant, wrong owner 403, non-existent token 403, contract mismatch 403, expired pass 403, nanosecond-precision expiry 403, space mismatch 403, fail-closed RPC network failure 503, unknown space ID 404.
3. **Server Routing & Query-String Regression Suite** (`test/server-routing.unit.test.js`):
   - **11 passed**: Homepage serving, UTM query preservation, bundle serving, safe URL-encoded space path decoding, `AsyncLock` FIFO mutual exclusion under 25 concurrent tasks, error recovery unblocking, rapid concurrent atomic disk writes.
4. **Transferee HTTP Authorization Path** (`test/transferee-auth.rpc.test.js`):
   - **4 passed, 1 skipped**: On-chain token ownership confirmation, previous owner denied (403), transferee cross-space isolation (403), fresh nonce issuance. *Skipped test requires interactive human wallet signature.*
5. **Real-RPC Testnet Connectivity** (`test/verifier.rpc.test.js`):
   - **5 passed**: Live provider instantiation, view access key listing, non-existent key failure, fake key rejection, bad endpoint failure.
6. **Simulated Challenge Lifecycle** (`test/verifier.unit.test.js`):
   - **10 passed**: 32-byte nonce entropy, single-use consumption, replay attack prevention, expiry validation, account/recipient binding.
7. **Simulated Cryptographic Verifier** (`test/verifier.unit.test.js`):
   - **13 passed**: Ed25519 signature checks, tampered message rejection, tampered nonce rejection, recipient mismatch rejection, malformed signature rejection, FullAccess key requirement.
8. **Simulated Full Pipeline** (`test/verifier.unit.test.js`):
   - **2 passed**: End-to-end issue -> consume -> verify flow.

### Explanation of the 4 Skipped Tests
Four tests in `test/verifier.rpc.test.js` and `test/transferee-auth.rpc.test.js` are deliberately skipped in automated CI because they require live human approval in an interactive browser extension popup (Meteor Wallet) to sign challenges. They can be executed locally by setting `REAL_SIG=1` and exporting testnet wallet credentials.

---

## 6. Local Development

### Prerequisites
- Node.js >= 20.0.0 (tested on Node.js v24.21.0)
- npm >= 10.0.0

### Step 1: Clone & Install Dependencies
```bash
git clone https://github.com/0xBaqi/unseal.git
cd unseal
npm install
```

### Step 2: Environment Configuration
Create a `.env` file in the project root:

```bash
# Server Runtime
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

# On-Chain Configuration
NFT_CONTRACT_ID=unseal-nft-55335700.testnet
NEAR_RPC_URL=https://archival-rpc.testnet.near.org

# Cloudflare R2 Storage (Required for Live Production Bucket)
R2_ACCOUNT_ID=your_cloudflare_account_id
R2_ACCESS_KEY_ID=your_r2_access_key_id
R2_SECRET_ACCESS_KEY=your_r2_secret_access_key
R2_BUCKET_NAME=unseal-private
```

> **Note**: In development mode (`NODE_ENV=development` without R2 credentials), Unseal automatically utilizes an in-memory `MockR2Client` high-fidelity S3 adapter. In production (`NODE_ENV=production`), valid Cloudflare R2 credentials are used.

### Step 3: Build the Frontend Bundle
```bash
npm run build
```
This compiles `public/proof.js` into `public/proof.bundle.js` using `esbuild`.

### Step 4: Run the Complete Test Suite
```bash
npm test
```

### Step 5: Start the Server
```bash
npm start
```
The server will listen at `http://localhost:3000`.

---

## 7. Known Limitations & Scope Boundaries

1. **Single-Process Persistence**: Metadata persistence uses atomic JSON file swapping (`data/spaces.json` and `data/documents.json`) protected by an asynchronous FIFO mutex (`AsyncLock`). Horizontal scaling across multiple container instances requires a shared distributed transactional database (e.g., PostgreSQL or Cloudflare D1).
2. **Browser Extension Requirements**: Automated testnet RPC checks and mock verifications run headlessly; full interactive signing popups require testing in a desktop browser with a supported NEAR wallet extension (such as Meteor Wallet) installed.
3. **Invitation Links**: Currently, access passes must be explicitly minted or transferred on-chain. Off-chain signed invitation links are slated for a future milestone.

---

## 8. License

MIT License. Developed for the NEAR Protocol Hackathon.
