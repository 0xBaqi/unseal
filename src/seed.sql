-- ==============================================================================
-- Unseal Default Demo Spaces (seed.sql)
-- Seeds standard public testnet demo spaces for judges & visitors
-- ==============================================================================

INSERT INTO spaces (
  space_id, name, contract_id, required_token_id, issuer, is_public_demo, secret_payload, enforce_expiry, created_at, updated_at
)
VALUES
  (
    'space-alpha',
    'Unseal Alpha Demo Vault (Synthetic Testnet Space)',
    'unseal-nft-55335700.testnet',
    'pass-alpha-1',
    'baronal.testnet',
    1,
    '{"message":"Welcome to Unseal Alpha Demo Space. Access granted via verified NEP-171 NFT ownership.","timestamp":"2026-11-17T08:00:00.000Z","clearanceLevel":"GATE_A3_VERIFIED"}',
    1,
    datetime('now'),
    datetime('now')
  ),
  (
    'space-transfer',
    'Unseal Transferable Demo Space',
    'unseal-nft-55335700.testnet',
    'pass-transfer-493545',
    'baronal.testnet',
    1,
    '{"message":"Welcome to Unseal Transfer Test Space. Access granted via transferred NEP-171 NFT pass.","timestamp":"2026-11-17T08:00:00.000Z","clearanceLevel":"GATE_A3_TRANSFEREE_VERIFIED"}',
    1,
    datetime('now'),
    datetime('now')
  )
ON CONFLICT(space_id) DO UPDATE SET
  name = excluded.name,
  contract_id = excluded.contract_id,
  required_token_id = excluded.required_token_id,
  issuer = excluded.issuer,
  is_public_demo = excluded.is_public_demo,
  secret_payload = excluded.secret_payload,
  enforce_expiry = excluded.enforce_expiry,
  updated_at = excluded.updated_at;
