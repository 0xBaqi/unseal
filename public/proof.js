globalThis.process = globalThis.process || { env: {} };
globalThis.JS_SHA256_NO_NODE_JS = true;
import { Buffer } from "buffer";
globalThis.Buffer = Buffer;
globalThis.global = globalThis;

import { setupWalletSelector } from "@near-wallet-selector/core";
import { setupMeteorWallet } from "@near-wallet-selector/meteor-wallet";
import { MeteorWallet } from "../node_modules/@near-wallet-selector/meteor-wallet/node_modules/@meteorwallet/sdk/dist/index.js";

// ── Application State ────────────────────────────────────────────────────────

let selector = null;
let selectorWallet = null;
let meteorDirectWallet = null;
let accountId = null;
let currentSpaces = [];
let lastCapturedAuth = null;
let activeBlobUrl = null;

const DEFAULT_CONTRACT_ID = 'unseal-nft-55335700.testnet';
const TESTNET_RPC_URLS = [
  'https://archival-rpc.testnet.near.org',
  'https://test.rpc.fastnear.com',
  'https://rpc.testnet.near.org'
];

const $ = (id) => document.getElementById(id);

const log = (msg) => {
  if (window.__appLog) {
    window.__appLog(msg);
  } else {
    console.log('[UNSEAL]', msg);
    const box = $('activityLog');
    if (box) {
      const ts = new Date().toISOString().split('T')[1].slice(0, 8);
      box.textContent = `[${ts}] ${msg}\n` + box.textContent;
    }
  }
};

function showAlert(msg, isSuccess = false) {
  const el = $('globalAlert');
  if (!el) return;
  el.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => {
    if (el) el.style.display = 'none';
  }, 9000);
}

function base64ToUint8Array(base64) {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ── On-Chain RPC Queries (Direct Browser-to-RPC, finality: final) ───────────

async function queryOnChainNftToken(contractId, tokenId) {
  if (!contractId || !tokenId) return null;
  const body = JSON.stringify({
    jsonrpc: '2.0',
    id: 'unseal-query',
    method: 'query',
    params: {
      request_type: 'call_function',
      finality: 'final',
      account_id: contractId,
      method_name: 'nft_token',
      args_base64: window.btoa(JSON.stringify({ token_id: tokenId })),
    },
  });

  for (const rpcUrl of TESTNET_RPC_URLS) {
    try {
      const res = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const data = await res.json();
      if (data.result && data.result.result) {
        const rawStr = new TextDecoder().decode(new Uint8Array(data.result.result));
        if (rawStr && rawStr !== 'null') {
          return JSON.parse(rawStr);
        }
      }
      return null;
    } catch {
      // Try next failover endpoint
    }
  }
  return null;
}

// ── Spaces & State Management ──────────────────────────────────────────────

async function loadSpaces() {
  log('Fetching spaces from backend GET /spaces...');
  try {
    const res = await fetch('/spaces');
    const data = await res.json();
    if (data.ok && Array.isArray(data.spaces)) {
      currentSpaces = data.spaces;
      log(`Loaded ${currentSpaces.length} space(s) from backend.`);

      // Populate Vault space select
      const vaultSel = $('vaultSpaceSelect');
      const creatorSel = $('creatorUploadSpace');
      if (vaultSel) {
        vaultSel.innerHTML = currentSpaces.map(s => 
          `<option value="${s.spaceId}">${s.name} (${s.spaceId})</option>`
        ).join('');
      }
      if (creatorSel) {
        creatorSel.innerHTML = currentSpaces.map(s => 
          `<option value="${s.spaceId}">${s.name} (${s.spaceId}) — Creator: ${s.issuer}</option>`
        ).join('');
      }

      await updateSelectedSpaceView();
    }
  } catch (err) {
    log(`Failed to fetch spaces: ${err.message}`);
  }
}

async function updateSelectedSpaceView() {
  const sel = $('vaultSpaceSelect');
  if (!sel || !sel.value) return;
  const spaceId = sel.value;
  const space = currentSpaces.find(s => s.spaceId === spaceId);
  if (!space) return;

  $('vaultSpaceName').textContent = space.name || space.spaceId;
  $('vaultRequiredToken').textContent = space.requiredTokenId || 'None';
  $('vaultContractId').textContent = space.contractId || DEFAULT_CONTRACT_ID;
  $('vaultIssuer').textContent = space.issuer || 'Unknown';

  // Document status
  const docStatusEl = $('vaultDocStatus');
  if (space.hasDocument && space.documentInfo) {
    docStatusEl.innerHTML = `<span class="badge badge-success">📄 Ready (${formatBytes(space.documentInfo.size)})</span>`;
  } else {
    docStatusEl.innerHTML = `<span class="badge badge-warning">⚠️ No Document Uploaded</span>`;
  }

  // Live on-chain query at finality: 'final'
  $('vaultOnChainOwner').textContent = 'Querying testnet RPC...';
  const badgeEl = $('vaultAccessBadge');
  const unlockBtn = $('btnUnlockDocument');

  const token = await queryOnChainNftToken(space.contractId, space.requiredTokenId);
  if (token) {
    $('vaultOnChainOwner').textContent = token.owner_id;

    if (accountId && token.owner_id === accountId) {
      badgeEl.innerHTML = `
        <div class="badge badge-success" style="font-size: 0.85rem; padding: 0.45rem 0.75rem;">
          ✓ On-Chain Verified: You own pass "${space.requiredTokenId}"! Ready to unlock.
        </div>`;
      if (unlockBtn) unlockBtn.disabled = false;
    } else {
      badgeEl.innerHTML = `
        <div class="badge badge-error" style="font-size: 0.85rem; padding: 0.45rem 0.75rem;">
          🔒 Restricted: Required pass "${space.requiredTokenId}" is owned by "${token.owner_id}".
        </div>`;
      if (unlockBtn) unlockBtn.disabled = !accountId;
    }
  } else {
    $('vaultOnChainOwner').textContent = 'Token Not Found on Contract';
    badgeEl.innerHTML = `
      <div class="badge badge-warning" style="font-size: 0.85rem; padding: 0.45rem 0.75rem;">
        ⚠️ Token "${space.requiredTokenId}" is not yet minted on contract "${space.contractId}".
      </div>`;
  }
}

// ── Wallet Connection ──────────────────────────────────────────────────────

function onAccountConnected(accId) {
  accountId = accId;
  $('lblAccount').textContent = accId;
  $('btnConnect').style.display = 'none';
  $('btnDisconnect').style.display = 'inline-flex';
  
  if ($('btnUnlockDocument')) $('btnUnlockDocument').disabled = false;
  if ($('btnUploadDoc')) $('btnUploadDoc').disabled = false;
  if ($('btnCreateSpace')) $('btnCreateSpace').disabled = false;
  if ($('btnMintPass')) $('btnMintPass').disabled = false;
  if ($('btnTransferPass')) $('btnTransferPass').disabled = false;
  if ($('btnSignChallengeOnly')) $('btnSignChallengeOnly').disabled = false;

  log(`Account connected: ${accId}`);
  showAlert(`Connected as ${accId}`, true);
  updateSelectedSpaceView();
}

function onAccountDisconnected() {
  accountId = null;
  selectorWallet = null;
  $('lblAccount').textContent = 'Not Connected';
  $('btnConnect').style.display = 'inline-flex';
  $('btnDisconnect').style.display = 'none';

  if ($('btnUnlockDocument')) $('btnUnlockDocument').disabled = true;
  if ($('btnUploadDoc')) $('btnUploadDoc').disabled = true;
  if ($('btnCreateSpace')) $('btnCreateSpace').disabled = true;
  if ($('btnMintPass')) $('btnMintPass').disabled = true;
  if ($('btnTransferPass')) $('btnTransferPass').disabled = true;
  if ($('btnSignChallengeOnly')) $('btnSignChallengeOnly').disabled = true;

  closeDocumentViewer();
  log('Wallet disconnected.');
  updateSelectedSpaceView();
}

async function connectWallet() {
  log('Opening Meteor Wallet connection...');
  try {
    if (!selector) await initSelector();
    if (selector) {
      selectorWallet = await selector.wallet("meteor-wallet");
      const accounts = await selectorWallet.signIn({ contractId: "" });
      if (accounts && accounts.length > 0) {
        onAccountConnected(accounts[0].accountId);
        return;
      }
    }
  } catch (err) {
    log(`Selector note: ${err.message}. Trying direct Meteor SDK...`);
  }

  // Fallback to direct Meteor SDK
  try {
    if (!meteorDirectWallet) {
      meteorDirectWallet = new MeteorWallet({ networkId: "testnet" });
    }
    const accounts = await meteorDirectWallet.requestSignIn({ contract_id: "" });
    if (accounts?.payload?.accountId) {
      onAccountConnected(accounts.payload.accountId);
      return;
    }
  } catch (err) {
    log(`Direct Meteor connection warning: ${err.message}`);
  }

  showAlert('Could not automatically connect. Click "⚙️ Manual" to input your testnet account directly.');
}

async function disconnectWallet() {
  try {
    if (selectorWallet) await selectorWallet.signOut();
    if (meteorDirectWallet) await meteorDirectWallet.signOut();
  } catch (e) {
    console.error(e);
  }
  onAccountDisconnected();
}

function setManualAccount() {
  const input = $('txtManualAccount');
  const val = input ? input.value.trim() : '';
  if (!val) {
    showAlert('Please enter your testnet account ID (e.g. yourname.testnet)');
    return;
  }
  onAccountConnected(val);
}

// ── NEP-413 Challenge & Signing ────────────────────────────────────────────

async function fetchChallenge(accId) {
  log(`Requesting nonce challenge from POST /challenge for ${accId}...`);
  const res = await fetch('/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId: accId }),
  });
  const data = await res.json();
  if (!data.nonceB64) {
    throw new Error(data.error || 'Failed to obtain challenge nonce');
  }
  log(`Nonce challenge issued. Nonce: ${data.nonceB64.slice(0, 16)}... Expires: ${new Date(data.expiresAt).toLocaleTimeString()}`);
  return data;
}

async function signChallengeWithWallet(challenge) {
  log('Prompting wallet for NEP-413 message signature...');
  const nonceBytes = base64ToUint8Array(challenge.nonceB64);
  let signed = null;

  // Try selector wallet
  if (selectorWallet && typeof selectorWallet.signMessage === 'function') {
    try {
      signed = await selectorWallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: nonceBytes,
      });
    } catch (err) {
      log(`Selector sign notice: ${err.message}. Trying direct Meteor SDK...`);
    }
  }

  // Try direct Meteor SDK
  if (!signed) {
    try {
      if (!meteorDirectWallet) {
        meteorDirectWallet = new MeteorWallet({ networkId: "testnet" });
      }
      const response = await meteorDirectWallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: nonceBytes,
        accountId,
      });
      signed = response.payload || response;
    } catch (err) {
      log(`Direct Meteor signMessage error: ${err.message}`);
      throw err;
    }
  }

  if (!signed || !signed.signature) {
    throw new Error('Wallet signature was cancelled or failed to return signature');
  }

  log(`NEP-413 signature captured from ${signed.accountId || accountId}`);
  return {
    accountId: signed.accountId || accountId,
    publicKey: signed.publicKey,
    signatureB64: signed.signature,
  };
}

// ── Holder Flow: Document Unlock & PDF Viewer ──────────────────────────────

async function unlockDocument() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }

  const sel = $('vaultSpaceSelect');
  const spaceId = sel ? sel.value : null;
  if (!spaceId) {
    showAlert('Please select a space to unlock.');
    return;
  }

  const statusEl = $('vaultUnlockStatus');
  const unlockBtn = $('btnUnlockDocument');
  unlockBtn.disabled = true;
  statusEl.textContent = 'Step 1/3: Requesting challenge...';

  try {
    const challenge = await fetchChallenge(accountId);

    statusEl.textContent = 'Step 2/3: Approve signature in wallet...';
    const signRes = await signChallengeWithWallet(challenge);

    lastCapturedAuth = {
      accountId: signRes.accountId,
      publicKey: signRes.publicKey,
      signatureB64: signRes.signatureB64,
      nonceB64: challenge.nonceB64,
      recipient: challenge.recipient,
      message: challenge.message,
    };
    enableAuditButtons();

    statusEl.textContent = 'Step 3/3: Verifying on-chain ownership at finality: "final"...';
    log(`Submitting signed challenge to POST /space/${spaceId}/content...`);

    const res = await fetch(`/space/${spaceId}/content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...lastCapturedAuth,
        spaceId,
      }),
    });

    if (res.status === 200) {
      log('HTTP 200 OK — On-chain ownership confirmed! Streaming PDF document...');
      const blob = await res.blob();
      const sha256 = res.headers.get('x-unseal-sha256') || 'Verified';
      const disposition = res.headers.get('content-disposition') || '';
      const filenameMatch = disposition.match(/filename="([^"]+)"/);
      const filename = filenameMatch ? filenameMatch[1] : `${spaceId}-document.pdf`;

      renderPdfViewer({
        blob,
        filename,
        size: blob.size,
        sha256,
      });

      statusEl.textContent = '✅ Document unlocked and decrypted!';
      showAlert(`Document "${filename}" unlocked successfully!`, true);
    } else {
      const errData = await res.json().catch(() => ({ error: 'Access denied' }));
      log(`HTTP ${res.status} Access Rejection: ${JSON.stringify(errData)}`);
      statusEl.textContent = `❌ ${errData.code || 'ACCESS_DENIED'}`;
      showAlert(`HTTP ${res.status} ${errData.code}: ${errData.error || 'Access Denied'}`);
      closeDocumentViewer();
    }
  } catch (err) {
    log(`Unlock error: ${err.message}`);
    statusEl.textContent = `Error: ${err.message}`;
    showAlert(`Error: ${err.message}`);
  } finally {
    unlockBtn.disabled = false;
  }
}

function renderPdfViewer({ blob, filename, size, sha256 }) {
  if (activeBlobUrl) {
    URL.revokeObjectURL(activeBlobUrl);
  }
  activeBlobUrl = URL.createObjectURL(blob);

  const container = $('viewerContainer');
  const frame = $('pdfFrame');
  const titleEl = $('viewerDocTitle');
  const sizeEl = $('viewerDocSize');
  const shaEl = $('viewerDocSha256');

  if (titleEl) titleEl.textContent = filename;
  if (sizeEl) sizeEl.textContent = formatBytes(size);
  if (shaEl) shaEl.textContent = `SHA-256: ${sha256.slice(0, 16)}...`;
  if (frame) frame.src = activeBlobUrl + '#toolbar=1';
  if (container) {
    container.style.display = 'block';
    container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function closeDocumentViewer() {
  if (activeBlobUrl) {
    URL.revokeObjectURL(activeBlobUrl);
    activeBlobUrl = null;
  }
  const frame = $('pdfFrame');
  const container = $('viewerContainer');
  if (frame) frame.src = 'about:blank';
  if (container) container.style.display = 'none';
  log('Document viewer closed and blob memory revoked.');
}

// ── Creator Flow: Document Upload & Space Creation ─────────────────────────

async function uploadDocument() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }

  const spaceSel = $('creatorUploadSpace');
  const spaceId = spaceSel ? spaceSel.value : null;
  if (!spaceId) {
    showAlert('Please select a target space.');
    return;
  }

  const fileInput = $('fileUploadPdf');
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showAlert('Please choose a PDF file to upload.');
    return;
  }

  const file = fileInput.files[0];
  if (file.size > 15 * 1024 * 1024) {
    showAlert('File exceeds maximum size of 15 MB.');
    return;
  }

  const uploadBtn = $('btnUploadDoc');
  uploadBtn.disabled = true;
  uploadBtn.textContent = 'Reading & Verifying PDF...';

  try {
    // 1. Read file as ArrayBuffer & validate PDF magic bytes "%PDF-"
    const arrayBuf = await file.arrayBuffer();
    const head = new Uint8Array(arrayBuf.slice(0, 5));
    const magic = String.fromCharCode(...head);
    if (magic !== '%PDF-') {
      throw new Error('Selected file does not have valid PDF magic bytes ("%PDF-").');
    }

    const pdfBase64 = arrayBufferToBase64(arrayBuf);

    // 2. Obtain NEP-413 challenge
    uploadBtn.textContent = 'Prompting Wallet Signature...';
    const challenge = await fetchChallenge(accountId);

    // 3. Sign challenge with creator wallet
    const signRes = await signChallengeWithWallet(challenge);

    // 4. Send to POST /space/:spaceId/upload
    uploadBtn.textContent = 'Uploading to Private Vault...';
    log(`Submitting validated PDF (${formatBytes(file.size)}) to POST /space/${spaceId}/upload...`);

    const spaceObj = currentSpaces.find(s => s.spaceId === spaceId);
    const res = await fetch(`/space/${spaceId}/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: signRes.accountId,
        publicKey: signRes.publicKey,
        signatureB64: signRes.signatureB64,
        nonceB64: challenge.nonceB64,
        recipient: challenge.recipient,
        message: challenge.message,
        spaceId,
        name: spaceObj?.name || spaceId,
        contractId: spaceObj?.contractId || DEFAULT_CONTRACT_ID,
        requiredTokenId: spaceObj?.requiredTokenId || `pass-${spaceId}-1`,
        filename: file.name,
        pdfBase64,
      }),
    });

    const data = await res.json();
    if (res.status === 200 && data.ok) {
      log(`Upload successful! Receipt: ${JSON.stringify(data.upload)}`);
      showAlert(`PDF uploaded successfully to "${spaceId}"!`, true);

      const receiptBox = $('uploadReceipt');
      const receiptJson = $('uploadReceiptJson');
      if (receiptBox) receiptBox.style.display = 'block';
      if (receiptJson) receiptJson.textContent = JSON.stringify(data.upload, null, 2);

      await loadSpaces();
    } else {
      log(`Upload error HTTP ${res.status}: ${JSON.stringify(data)}`);
      showAlert(`Upload Failed (HTTP ${res.status}): ${data.code} — ${data.error}`);
    }
  } catch (err) {
    log(`Upload error: ${err.message}`);
    showAlert(`Error: ${err.message}`);
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = '📤 Sign Challenge & Upload to Private Vault';
  }
}

async function createSpace() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }

  const spaceId = $('txtNewSpaceId')?.value.trim();
  const name = $('txtNewSpaceName')?.value.trim();
  const contractId = $('txtNewContractId')?.value.trim();
  const requiredTokenId = $('txtNewTokenId')?.value.trim();
  const statusEl = $('createSpaceStatus');

  if (!spaceId || !name || !contractId || !requiredTokenId) {
    showAlert('All space registration fields are required.');
    return;
  }

  statusEl.textContent = 'Requesting challenge...';
  try {
    const challenge = await fetchChallenge(accountId);
    statusEl.textContent = 'Approve signature in wallet...';
    const signRes = await signChallengeWithWallet(challenge);

    statusEl.textContent = 'Registering space...';
    const res = await fetch('/spaces', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: signRes.accountId,
        publicKey: signRes.publicKey,
        signatureB64: signRes.signatureB64,
        nonceB64: challenge.nonceB64,
        recipient: challenge.recipient,
        message: challenge.message,
        spaceId,
        name,
        contractId,
        requiredTokenId,
      }),
    });

    const data = await res.json();
    if (res.status === 200 && data.ok) {
      statusEl.textContent = '✅ Space registered!';
      showAlert(`Space "${name}" registered successfully!`, true);
      await loadSpaces();
      if ($('creatorUploadSpace')) $('creatorUploadSpace').value = spaceId;
      if ($('vaultSpaceSelect')) $('vaultSpaceSelect').value = spaceId;
      await updateSelectedSpaceView();
    } else {
      statusEl.textContent = `❌ ${data.code || 'Registration failed'}`;
      showAlert(`Registration failed: ${data.error || data.code}`);
    }
  } catch (err) {
    statusEl.textContent = `Error: ${err.message}`;
    showAlert(`Error: ${err.message}`);
  }
}

// ── Pass & NFT Management ──────────────────────────────────────────────────

async function inspectToken() {
  const input = $('txtInspectTokenId');
  const tokenId = input ? input.value.trim() : '';
  const out = $('inspectTokenOutput');
  if (!tokenId) {
    showAlert('Please enter a token ID to inspect.');
    return;
  }

  out.textContent = `Querying NEAR Testnet RPC for token "${tokenId}" at finality: 'final'...`;
  try {
    const token = await queryOnChainNftToken(DEFAULT_CONTRACT_ID, tokenId);
    if (token) {
      out.textContent = JSON.stringify(token, null, 2);
      log(`Inspected token ${tokenId}: Owner is ${token.owner_id}`);
    } else {
      out.textContent = `Token "${tokenId}" not found on contract "${DEFAULT_CONTRACT_ID}".`;
    }
  } catch (err) {
    out.textContent = `Error querying RPC: ${err.message}`;
  }
}

// ── Universal Wallet Transaction Execution (Meteor / Selector / Injected) ───

async function executeTransaction({ receiverId, actions }) {
  log(`Executing transaction on ${receiverId}...`);

  // 1. Selector wallet (if connected via Wallet Selector)
  if (selectorWallet) {
    if (typeof selectorWallet.signAndSendTransaction === 'function') {
      return await selectorWallet.signAndSendTransaction({
        signerId: accountId,
        receiverId,
        actions,
      });
    }
    if (typeof selectorWallet.signAndSendTransactions === 'function') {
      const outcomes = await selectorWallet.signAndSendTransactions({
        transactions: [{ signerId: accountId, receiverId, actions }],
      });
      return outcomes?.[0];
    }
  }

  // 2. Direct Meteor Wallet SDK or injected window.meteorWallet
  const direct = meteorDirectWallet || (typeof window !== 'undefined' ? window.meteorWallet : null);
  if (direct) {
    // If it has account() method returning ConnectedMeteorWalletAccount
    if (typeof direct.account === 'function') {
      try {
        const acc = await direct.account();
        if (typeof acc.signAndSendTransaction_direct === 'function') {
          return await acc.signAndSendTransaction_direct({ receiverId, actions });
        }
        if (typeof acc.signAndSendTransaction === 'function') {
          return await acc.signAndSendTransaction({ receiverId, actions });
        }
      } catch (err) {
        log(`Direct Meteor account notice: ${err.message}`);
      }
    }
    // If it has requestSignTransactions
    if (typeof direct.requestSignTransactions === 'function') {
      const outcomes = await direct.requestSignTransactions({
        transactions: [{ receiverId, actions, signerId: accountId }],
      });
      return outcomes?.[0];
    }
    // If it directly has signAndSendTransaction
    if (typeof direct.signAndSendTransaction === 'function') {
      return await direct.signAndSendTransaction({ receiverId, actions });
    }
  }

  // 3. Fallback: window.near injected provider
  if (typeof window !== 'undefined' && window.near && typeof window.near.signAndSendTransaction === 'function') {
    return await window.near.signAndSendTransaction({ receiverId, actions });
  }

  throw new Error('No connected wallet with transaction signing capability found. Please ensure your Meteor Wallet is connected.');
}

async function mintPass() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }

  const tokenId = $('txtMintTokenId')?.value.trim();
  const recipient = $('txtMintRecipient')?.value.trim();
  const spaceId = $('txtMintSpaceId')?.value.trim();
  const statusEl = $('mintStatus');

  if (!tokenId || !recipient) {
    showAlert('Token ID and Recipient Account are required.');
    return;
  }

  statusEl.textContent = `Prompting wallet to mint "${tokenId}" to ${recipient}...`;
  log(`Minting pass "${tokenId}" for space "${spaceId}" to ${recipient}...`);

  try {
    const actions = [{
      type: 'FunctionCall',
      params: {
        methodName: 'nft_mint',
        args: {
          token_id: tokenId,
          token_owner_id: recipient,
          token_metadata: {
            title: `Unseal Pass: ${spaceId}`,
            description: `NFT Access Pass for space ${spaceId}`,
            extra: JSON.stringify({ space_id: spaceId }),
          },
        },
        gas: '30000000000000',
        deposit: '10000000000000000000000', // 0.01 NEAR storage deposit
      },
    }];

    const outcome = await executeTransaction({ receiverId: DEFAULT_CONTRACT_ID, actions });
    if (!outcome) {
      throw new Error('Transaction was cancelled or did not return an execution outcome.');
    }

    const txHash = outcome?.transaction?.hash || outcome?.transaction_outcome?.id || (typeof outcome === 'string' ? outcome : 'Confirmed');
    statusEl.textContent = `✅ Minted! Tx: ${txHash}`;
    log(`Access pass minted! Tx: ${txHash}`);
    showAlert(`Access pass "${tokenId}" minted to ${recipient}!`, true);
    await updateSelectedSpaceView();
  } catch (err) {
    statusEl.textContent = `❌ Mint failed: ${err.message}`;
    log(`Mint error: ${err.message}`);
    showAlert(`Mint failed: ${err.message}`);
  }
}

async function transferPass() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }

  const tokenId = $('txtTransferTokenId')?.value.trim();
  const recipient = $('txtTransferRecipient')?.value.trim();
  const statusEl = $('transferStatus');

  if (!tokenId || !recipient) {
    showAlert('Token ID and Recipient Account ID are required.');
    return;
  }

  statusEl.textContent = `Prompting wallet to transfer "${tokenId}" to ${recipient}...`;
  log(`Executing nft_transfer of "${tokenId}" to ${recipient}...`);

  try {
    const actions = [{
      type: 'FunctionCall',
      params: {
        methodName: 'nft_transfer',
        args: {
          receiver_id: recipient,
          token_id: tokenId,
          memo: 'Unseal pass transfer - live revocation demo',
        },
        gas: '30000000000000',
        deposit: '1', // 1 yoctoNEAR
      },
    }];

    const outcome = await executeTransaction({ receiverId: DEFAULT_CONTRACT_ID, actions });
    if (!outcome) {
      throw new Error('Transaction was cancelled or did not return an execution outcome.');
    }

    const txHash = outcome?.transaction?.hash || outcome?.transaction_outcome?.id || (typeof outcome === 'string' ? outcome : 'Confirmed');
    statusEl.textContent = `✅ Transferred! Tx: ${txHash}. Instant revocation active!`;
    log(`Pass transferred! Tx: ${txHash}`);
    showAlert(`Pass transferred! Previous owner revoked immediately.`, true);
    await updateSelectedSpaceView();
  } catch (err) {
    statusEl.textContent = `❌ Transfer failed: ${err.message}`;
    log(`Transfer error: ${err.message}`);
    showAlert(`Transfer failed: ${err.message}`);
  }
}

// ── Security & Audit Negative Tests ────────────────────────────────────────

function enableAuditButtons() {
  if ($('btnTestReplay')) $('btnTestReplay').disabled = !lastCapturedAuth;
  if ($('btnTestTampered')) $('btnTestTampered').disabled = !lastCapturedAuth;
  if ($('btnTestWrongRecipient')) $('btnTestWrongRecipient').disabled = !lastCapturedAuth;
}

async function signChallengeOnly() {
  if (!accountId) {
    showAlert('Please connect your testnet wallet first.');
    return;
  }
  try {
    const challenge = await fetchChallenge(accountId);
    const signRes = await signChallengeWithWallet(challenge);
    lastCapturedAuth = {
      accountId: signRes.accountId,
      publicKey: signRes.publicKey,
      signatureB64: signRes.signatureB64,
      nonceB64: challenge.nonceB64,
      recipient: challenge.recipient,
      message: challenge.message,
    };
    enableAuditButtons();

    const res = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(lastCapturedAuth),
    });
    const data = await res.json();

    const container = $('verifyResultContainer');
    const badge = $('verifyBadge');
    const out = $('verifyOutput');
    if (container) container.style.display = 'block';
    if (badge) {
      badge.innerHTML = data.ok
        ? '<span class="badge badge-success">✓ Cryptographic NEP-413 Signature Verified (HTTP 200)</span>'
        : `<span class="badge badge-error">✕ Verification Failed: ${data.code}</span>`;
    }
    if (out) out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    showAlert(`Signing error: ${err.message}`);
  }
}

async function testReplay() {
  if (!lastCapturedAuth) return;
  const out = $('auditOutput');
  out.style.display = 'block';
  out.textContent = 'Submitting already-consumed nonce to /verify...';
  log('[NEGATIVE AUDIT] Testing replay attack...');

  const res = await fetch('/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(lastCapturedAuth),
  });
  const data = await res.json();
  out.textContent = `REPLAY TEST (Expected 400 CHALLENGE_NOT_FOUND):\nHTTP ${res.status}\n${JSON.stringify(data, null, 2)}`;
  log(`Replay test: HTTP ${res.status} ${data.code || ''}`);
}

async function testTampered() {
  if (!lastCapturedAuth) return;
  const out = $('auditOutput');
  out.style.display = 'block';
  out.textContent = 'Submitting tampered signature with fresh challenge...';
  log('[NEGATIVE AUDIT] Testing tampered signature...');

  const ch = await fetchChallenge(lastCapturedAuth.accountId);
  const tamperedSig = 'A' + lastCapturedAuth.signatureB64.slice(1);

  const res = await fetch('/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...lastCapturedAuth,
      nonceB64: ch.nonceB64,
      signatureB64: tamperedSig,
    }),
  });
  const data = await res.json();
  out.textContent = `TAMPERED SIG TEST (Expected 401 BAD_SIGNATURE):\nHTTP ${res.status}\n${JSON.stringify(data, null, 2)}`;
  log(`Tampered sig test: HTTP ${res.status} ${data.code || ''}`);
}

async function testWrongRecipient() {
  if (!lastCapturedAuth) return;
  const out = $('auditOutput');
  out.style.display = 'block';
  out.textContent = 'Submitting wrong recipient with fresh challenge...';
  log('[NEGATIVE AUDIT] Testing wrong recipient...');

  const ch = await fetch('/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId: lastCapturedAuth.accountId, recipient: 'attacker-site.com' }),
  }).then(r => r.json());

  const res = await fetch('/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...lastCapturedAuth,
      nonceB64: ch.nonceB64,
      recipient: 'attacker-site.com',
    }),
  });
  const data = await res.json();
  out.textContent = `WRONG RECIPIENT TEST (Expected 400/401 RECIPIENT_MISMATCH):\nHTTP ${res.status}\n${JSON.stringify(data, null, 2)}`;
  log(`Wrong recipient test: HTTP ${res.status} ${data.code || ''}`);
}

// ── Initialization & UI Event Binding ──────────────────────────────────────

async function initSelector() {
  try {
    selector = await setupWalletSelector({
      network: "testnet",
      modules: [setupMeteorWallet()],
    });
    const state = selector.store.getState();
    if (state.accounts && state.accounts.length > 0) {
      onAccountConnected(state.accounts[0].accountId);
    }
  } catch (err) {
    log(`Wallet selector init note: ${err.message}`);
  }
}

function setupUI() {
  log('Binding Unseal UI handlers...');

  // Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      if ($(targetId)) $(targetId).style.display = 'block';
    };
  });

  // Wallet
  if ($('btnConnect')) $('btnConnect').onclick = connectWallet;
  if ($('btnDisconnect')) $('btnDisconnect').onclick = disconnectWallet;
  if ($('btnToggleManual')) {
    $('btnToggleManual').onclick = () => {
      const card = $('manualConnectCard');
      card.style.display = card.style.display === 'none' || !card.style.display ? 'block' : 'none';
    };
  }
  if ($('btnSetManualAccount')) $('btnSetManualAccount').onclick = setManualAccount;

  // Vault
  if ($('vaultSpaceSelect')) $('vaultSpaceSelect').onchange = updateSelectedSpaceView;
  if ($('btnRefreshSpaces')) $('btnRefreshSpaces').onclick = loadSpaces;
  if ($('btnUnlockDocument')) $('btnUnlockDocument').onclick = unlockDocument;
  if ($('btnCloseViewer')) $('btnCloseViewer').onclick = closeDocumentViewer;

  // Creator
  if ($('btnUploadDoc')) $('btnUploadDoc').onclick = uploadDocument;
  if ($('fileUploadPdf')) {
    $('fileUploadPdf').onchange = (e) => {
      const file = e.target.files[0];
      const notice = $('fileInfoNotice');
      if (file && notice) {
        notice.textContent = `Selected: "${file.name}" (${formatBytes(file.size)})`;
      }
    };
  }
  if ($('btnCreateSpace')) $('btnCreateSpace').onclick = createSpace;

  // Pass Management
  if ($('btnInspectToken')) $('btnInspectToken').onclick = inspectToken;
  if ($('btnMintPass')) $('btnMintPass').onclick = mintPass;
  if ($('btnTransferPass')) $('btnTransferPass').onclick = transferPass;

  // Security Audit
  if ($('btnSignChallengeOnly')) $('btnSignChallengeOnly').onclick = signChallengeOnly;
  if ($('btnTestReplay')) $('btnTestReplay').onclick = testReplay;
  if ($('btnTestTampered')) $('btnTestTampered').onclick = testTampered;
  if ($('btnTestWrongRecipient')) $('btnTestWrongRecipient').onclick = testWrongRecipient;

  // Load spaces and init
  loadSpaces();
  initSelector();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupUI);
} else {
  setupUI();
}
