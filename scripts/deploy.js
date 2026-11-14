/**
 * scripts/deploy.js — NEAR Testnet Deployment for Gate A.3 NEP-171 Contract.
 *
 * 1. Generates an ephemeral keypair for a dedicated testnet contract account.
 * 2. Creates and funds the account via NEAR testnet helper faucet (~10 NEAR).
 * 3. Deploys the compiled NEP-171 WASM (contract/target/wasm32-unknown-unknown/release/unseal_nft.wasm).
 * 4. Initializes the contract via `new_default_meta({ owner_id: "baronal.testnet" })`.
 * 5. Mints the real access pass `pass-alpha-1` to `baronal.testnet`.
 * 6. Verifies on-chain token creation and ownership via `nft_token`.
 * 7. Saves deployment artifact to `deployment.testnet.json`.
 *
 * Zero sensitive keys or seed phrases are logged or exposed.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Account,
  JsonRpcProvider,
  KeyPair,
  KeyPairSigner,
  parseNearAmount,
} from 'near-api-js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = join(__dirname, '..');
const WASM_PATH = join(ROOT_DIR, 'contract/target/wasm32-unknown-unknown/release/unseal_nft.wasm');
const DEPLOYMENT_OUT = join(ROOT_DIR, 'deployment.testnet.json');

import { createProvider, TESTNET_RPC_URL } from '../src/verifier.js';
const RPC_URL = TESTNET_RPC_URL;
const OWNER_ACCOUNT_ID = process.env.OWNER_ACCOUNT_ID || 'baronal.testnet';
const FAUCET_URL = 'https://helper.testnet.near.org/account';

async function main() {
  console.log('=== UNSEAL GATE A.3: TESTNET CONTRACT DEPLOYMENT ===');
  console.log(`Target RPC: ${RPC_URL}`);
  console.log(`Contract Owner: ${OWNER_ACCOUNT_ID}`);

  // 1. Read compiled WASM
  const wasmBytes = readFileSync(WASM_PATH);
  console.log(`Read WASM binary: ${(wasmBytes.length / 1024).toFixed(1)} KB`);

  // 2. Generate deployment keypair
  const contractKeyPair = KeyPair.fromRandom('ed25519');
  const contractPublicKey = contractKeyPair.getPublicKey().toString();
  const contractAccountId = `unseal-nft-${Date.now().toString().slice(-8)}.testnet`;
  console.log(`Generated contract account: ${contractAccountId}`);
  console.log(`Public key: ${contractPublicKey}`);

  // Save contract key to gitignored local file for test runner minting
  const contractKeysPath = join(ROOT_DIR, '.testnet-keys.json');
  writeFileSync(contractKeysPath, JSON.stringify({
    contractId: contractAccountId,
    secretKey: contractKeyPair.toString(),
    publicKey: contractPublicKey,
  }, null, 2), { mode: 0o600 });

  // 3. Create account via testnet faucet helper
  console.log('Requesting account creation and funding from testnet faucet...');
  const faucetRes = await fetch(FAUCET_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      newAccountId: contractAccountId,
      newAccountPublicKey: contractPublicKey,
    }),
  });

  if (!faucetRes.ok) {
    const text = await faucetRes.text();
    throw new Error(`Faucet account creation failed (${faucetRes.status}): ${text}`);
  }

  const faucetData = await faucetRes.json();
  const faucetTxHash = faucetData.transaction?.hash || 'confirmed';
  console.log(`Account created successfully! Faucet Tx: ${faucetTxHash}`);

  // 4. Connect to account
  const provider = createProvider();
  const signer = new KeyPairSigner(contractKeyPair);
  const contractAccount = new Account(contractAccountId, provider, signer);

  // 5. Deploy WASM
  console.log('Deploying WASM to testnet...');
  const deployOutcome = await contractAccount.deployContract(wasmBytes);
  const deployTxHash = deployOutcome.transaction?.hash || deployOutcome.transaction_outcome?.id;
  console.log(`Contract deployed! Tx: ${deployTxHash}`);

  // 6. Initialize Contract
  console.log(`Initializing contract with owner: ${OWNER_ACCOUNT_ID}...`);
  const initOutcome = await contractAccount.callFunctionRaw({
    contractId: contractAccountId,
    methodName: 'new_default_meta',
    args: { owner_id: OWNER_ACCOUNT_ID },
    gas: 30000000000000n, // 30 TGas
  });
  const initTxHash = initOutcome.transaction?.hash || initOutcome.transaction_outcome?.id;
  console.log(`Contract initialized! Tx: ${initTxHash}`);

  // 7. Mint access pass for baronal.testnet
  const tokenId = 'pass-alpha-1';
  console.log(`Minting access pass "${tokenId}" to "${OWNER_ACCOUNT_ID}"...`);
  const mintOutcome = await contractAccount.callFunctionRaw({
    contractId: contractAccountId,
    methodName: 'nft_mint',
    args: {
      token_id: tokenId,
      token_owner_id: OWNER_ACCOUNT_ID,
      token_metadata: {
        title: 'Unseal Alpha Access Pass #1',
        description: 'Gate A.3 on-chain access pass for space-alpha',
        media: null,
        media_hash: null,
        copies: 1,
        issued_at: Date.now().toString(),
        expires_at: null,
        starts_at: null,
        updated_at: null,
        extra: JSON.stringify({ space_id: 'space-alpha' }),
        reference: null,
        reference_hash: null,
      },
    },
    deposit: BigInt(parseNearAmount('0.02')), // storage deposit for token record
    gas: 50000000000000n, // 50 TGas
  });
  const mintTxHash = mintOutcome.transaction?.hash || mintOutcome.transaction_outcome?.id;
  console.log(`Access pass minted! Tx: ${mintTxHash}`);

  // 7b. Create Bob testnet account and mint pass-transfer-proof for revocation testing
  console.log('Creating Bob testnet account for transfer & revocation proof...');
  const bobKeyPair = KeyPair.fromRandom('ed25519');
  const bobPublicKey = bobKeyPair.getPublicKey().toString();
  const bobAccountId = `bob-${Date.now().toString().slice(-8)}.testnet`;
  const bobFaucetRes = await fetch(FAUCET_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      newAccountId: bobAccountId,
      newAccountPublicKey: bobPublicKey,
    }),
  });
  if (!bobFaucetRes.ok) throw new Error('Failed to create Bob testnet account');
  console.log(`Created Bob account: ${bobAccountId}`);

  const transferTokenId = 'pass-transfer-proof';
  console.log(`Minting "${transferTokenId}" to "${bobAccountId}"...`);
  const mintBobOutcome = await contractAccount.callFunctionRaw({
    contractId: contractAccountId,
    methodName: 'nft_mint',
    args: {
      token_id: transferTokenId,
      token_owner_id: bobAccountId,
      token_metadata: {
        title: 'Unseal Transferable Access Pass',
        description: 'Gate A.3 on-chain revocation test pass',
        copies: 1,
        issued_at: Date.now().toString(),
        extra: JSON.stringify({ space_id: 'space-transfer' }),
      },
    },
    deposit: BigInt(parseNearAmount('0.02')),
    gas: 50000000000000n,
  });
  const mintBobTxHash = mintBobOutcome.transaction?.hash || mintBobOutcome.transaction_outcome?.id;
  console.log(`Transferable pass minted! Tx: ${mintBobTxHash}`);

  // 8. Verify token via on-chain view call
  console.log(`Querying on-chain state: nft_token("${tokenId}")...`);
  const tokenQuery = await provider.query({
    request_type: 'call_function',
    finality: 'final',
    account_id: contractAccountId,
    method_name: 'nft_token',
    args_base64: Buffer.from(JSON.stringify({ token_id: tokenId })).toString('base64'),
  });
  const verifiedToken = JSON.parse(Buffer.from(tokenQuery.result).toString('utf8'));
  console.log('On-chain token verified:', JSON.stringify(verifiedToken, null, 2));

  if (verifiedToken.owner_id !== OWNER_ACCOUNT_ID) {
    throw new Error(`Owner mismatch! Expected ${OWNER_ACCOUNT_ID}, got ${verifiedToken.owner_id}`);
  }

  // 8b. Save Bob credentials locally for test runner (gitignored)
  const bobAuthPath = join(ROOT_DIR, '.testnet-bob.json');
  writeFileSync(bobAuthPath, JSON.stringify({
    accountId: bobAccountId,
    secretKey: bobKeyPair.toString(),
    publicKey: bobPublicKey,
    tokenId: transferTokenId,
  }, null, 2));

  // 9. Save deployment details
  const deploymentInfo = {
    network: 'testnet',
    rpcUrl: RPC_URL,
    contractId: contractAccountId,
    ownerId: OWNER_ACCOUNT_ID,
    tokenId,
    tokenExtra: verifiedToken.metadata?.extra,
    transferTokenId,
    bobAccountId,
    transactions: {
      faucetAccountCreate: faucetTxHash,
      deployContract: deployTxHash,
      initialize: initTxHash,
      mintPass: mintTxHash,
      mintTransferPass: mintBobTxHash,
    },
    deployedAt: new Date().toISOString(),
  };

  writeFileSync(DEPLOYMENT_OUT, JSON.stringify(deploymentInfo, null, 2));
  console.log(`Deployment recorded in ${DEPLOYMENT_OUT}`);
  console.log('=== GATE A.3 DEPLOYMENT COMPLETE ===');
}

main().catch((err) => {
  console.error('DEPLOYMENT FAILED:', err);
  process.exit(1);
});
