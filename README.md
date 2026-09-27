# dkg-admin

Operator-side daemon/CLI for participating in a RedPallas FROST DKG (Orchard spend-auth, RedPallas) and exporting an encrypted per-operator key package blob for `tss-host`.

This repo is part of the `junocash-tools` org.

## Build / Test

- `make build`
- `make test`
- `make test-e2e` (ignored heavy regtest interop e2e)
- `make test-all`
- `make lint`

## What This Tool Does

`dkg-admin` runs on each operator signing host and implements:

- RedPallas FROST DKG (`reddsa::frost::redpallas::keys::dkg`) part1/part2/part3.
- Online ceremony mode: an mTLS gRPC service that a coordinator (`dkg-ceremony`) drives.
- Offline ceremony mode: import/export of Round 1 and Round 2 packages via files for airgapped routing.
- Smoke signing (standard + randomized) to validate Orchard spend-auth compatibility.
- Encrypted export of the operator `KeyPackage` + shared `PublicKeyPackage` in a stable, versioned envelope.

## Identity + Config Pinning

`dkg-admin` must be started with a local JSON config (`AdminConfigV1`). The config pins:

- `ceremony_id` (UUID, required, included in ceremony hash)
- `roster_hash_hex` (or the full roster contents) to prevent “swap the roster” attacks.
- `operator_id` (stable string; recommended: lowercase hex Ethereum address).
- `identifier` (u16) assigned deterministically:
  - sort `operator_id` ascending
  - assign identifiers `1..=n` (non-zero)
- `threshold` and `max_signers`
- `network` (`mainnet`, `testnet`, `regtest`)

If any of these values mismatch the ceremony inputs, `dkg-admin` refuses to participate.

## Config Examples

Roster (`RosterV1`) example (online):

```json
{
  "roster_version": 1,
  "operators": [
    { "operator_id": "0x0000000000000000000000000000000000000001", "grpc_endpoint": "https://op1.example.com:8443" },
    { "operator_id": "0x0000000000000000000000000000000000000002", "grpc_endpoint": "https://op2.example.com:8443" },
    { "operator_id": "0x0000000000000000000000000000000000000003", "grpc_endpoint": "https://op3.example.com:8443" },
    { "operator_id": "0x0000000000000000000000000000000000000004", "grpc_endpoint": "https://op4.example.com:8443" },
    { "operator_id": "0x0000000000000000000000000000000000000005", "grpc_endpoint": "https://op5.example.com:8443" }
  ]
}
```

Operator `AdminConfigV1` example (online service mode):

```json
{
  "config_version": 1,
  "ceremony_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "operator_id": "0x0000000000000000000000000000000000000001",
  "identifier": 1,
  "threshold": 3,
  "max_signers": 5,
  "network": "regtest",
  "roster": { "...": "see above" },
  "roster_hash_hex": "<sha256 hex>",
  "state_dir": "./state",
  "grpc": {
    "listen_addr": "0.0.0.0:8443",
    "tls_ca_cert_pem_path": "./tls/ca.pem",
    "tls_server_cert_pem_path": "./tls/server.pem",
    "tls_server_key_pem_path": "./tls/server.key",
    "tls_client_cert_pem_path": "./tls/client.pem",
    "tls_client_key_pem_path": "./tls/client.key",
    "tls_domain_name_override": "localhost"
  }
}
```

Offline ceremonies additionally require `age_identity_file`, and the roster must include each operator’s `age_recipient`:

```json
{
  "age_identity_file": "./age/identity.txt",
  "roster": {
    "roster_version": 1,
    "operators": [
      { "operator_id": "0x...01", "age_recipient": "age1..." },
      { "operator_id": "0x...02", "age_recipient": "age1..." }
    ],
    "coordinator_age_recipient": "age1..."
  }
}
```

## Online Ceremony (Service Mode)

In online mode, each operator runs an mTLS gRPC server and the coordinator drives the protocol.

### Operator Setup (5 Operators Example)

Assume `n=5`, `threshold=3`.

1. Coordinator publishes a roster with 5 `operator_id` values and the expected identifier mapping.
2. Each operator verifies:
   - their `operator_id`
   - their assigned `identifier` from the sort rule
   - the `roster_hash_hex`
3. Each operator configures:
   - `grpc.listen_addr` (e.g. `127.0.0.1:7001`)
   - server TLS cert/key signed by the ceremony CA
   - CA cert to validate the coordinator client cert
4. Each operator starts the service:

```bash
dkg-admin --config ./config.json serve
```

5. The coordinator runs `dkg-ceremony online ...` and on success publishes:
   - `KeysetManifest.json` (public)
   - `transcript/` (public, non-secret)

### Notes

- Round 2 packages are confidential; `dkg-admin` does not print them.
- Request validation is strict: unexpected caller, wrong roster hash / ceremony hash, or invalid sequencing aborts.
- `GetStatus` RPC is available for coordinator preflight/readiness checks and returns operator id, identifier, ceremony hash, phase, phase input hashes, and binary version/commit.
- Part2/Part3 are strict idempotent with input binding:
  - first successful input is committed in local binding state
  - same input returns cached-equivalent output
  - different input returns explicit mismatch error (`part2_input_mismatch` / `part3_input_mismatch`) without overwriting state
- mTLS is required. Each operator configures:
  - a server certificate (and key) signed by the ceremony CA
  - a CA certificate to validate the coordinator client certificate
  - (optional) `grpc.coordinator_client_cert_sha256` to pin the coordinator identity even if another client chains to the same CA

## Offline Ceremony (File Mode, Airgapped)

Offline mode uses files for routing. Round 2 packages are age-encrypted per-recipient.

### Requirements

- The roster must include `age_recipient` for each operator.
- Each operator must have an `age_identity_file` configured (or pass `--age-identity-file` to part3) to decrypt Round 2 packages addressed to them.
- (Optional) `roster.coordinator_age_recipient` can be set so each Round 2 package is additionally encrypted to the coordinator for routing.

### File Naming Conventions

- Round 1 output: `round1_<id>.bin`
- Round 2 outputs: `round2_to_<recv>_from_<sender>.age`

### Operator Steps (5 Operators Example)

1. Round 1 (generate your package):

```bash
dkg-admin --config ./config.json dkg part1 --out ./round1_out/round1_<id>.bin
```

Deliver your `round1_<id>.bin` to the coordinator.

2. Round 2 (compute and export encrypted packages to everyone else):

```bash
dkg-admin --config ./config.json dkg part2 \
  --round1-dir ./round1_in \
  --out-dir ./round2_out
```

Deliver all `round2_to_*_from_<id>.age` files to the coordinator. Treat these as confidential.

3. Round 3 (finalize with Round 1 + your received Round 2 packages):

```bash
dkg-admin --config ./config.json dkg part3 \
  --round1-dir ./round1_in \
  --round2-dir ./round2_to_me
```

On success, `dkg-admin` prints:

- `public_key_package_hash_hex=...` (must match across all operators)
- `ak_bytes_hex=...` (must be canonical)

## Exporting The Encrypted Key Package

After part3 succeeds, export a single encrypted blob usable by `tss-host`.

Targets:

- local file (mode `0600`, fsync)
- S3 object (strong put semantics), plus a `KeyImportReceipt.json`

Backends:

- age recipient encryption (offline portability)
- AWS KMS envelope encryption (AWS deployments)

Examples:

```bash
# age -> local file
dkg-admin --config ./config.json export-key-package \
  --age-recipient age1... \
  --out ./keypackage.age.json

# KMS -> local file
dkg-admin --config ./config.json export-key-package \
  --kms-key-id arn:aws:kms:... \
  --out ./keypackage.kms.json
```

## Smoke Signing

For compatibility testing, `dkg-admin` can produce FROST signing commitments and signature shares for a coordinator-provided `SigningPackage`, including randomized signing (per-action `alpha`).

CLI mode:

```bash
dkg-admin --config ./config.json smoke commit --message-file ./msg.bin --out ./commitments.bin
dkg-admin --config ./config.json smoke share --signing-package-file ./signing_package.bin --out ./sigshare.bin
```

Online mode uses the same primitives over gRPC.

## Production Spend-Auth Signing (`sign-spendauth`)

Use this command in production to sign `juno-txsign ext-prepare` requests with threshold RedPallas FROST using the operator roster and sealed DKG key packages.

Command:

```bash
dkg-admin --config ./config.json sign-spendauth \
  --session-id 0x<64-hex> \
  --requests ./signing_requests.v0.json \
  --out ./spend_auth_sigs.v0.json
```

Input contract (`--requests`):

- Must match `api/signing_requests.v0.schema.json` exactly.
- `version` must be `"v0"`.
- Unknown fields are rejected (`additionalProperties=false` behavior).
- `requests` must be non-empty.
- `action_index` must be unique (duplicate indices are rejected).
- `sighash`, `alpha`, `rk` must be strict 32-byte hex (64 chars, no `0x`).

Session and idempotency:

- `--session-id` is required and must be strict `0x` + 32-byte hex.
- Session state is durably persisted under `state/sign_spendauth/sessions/`.
- Key is `(session-id, request-set-hash)`.
- Re-running with the same inputs is idempotent and rewrites byte-identical output.
- Reusing a `session-id` with a different request set fails with `session_conflict`.
- Interrupted runs can be resumed safely after restart.

Output contract (`--out`):

- Must match `api/spend_auth_sigs.v0.schema.json`.
- `version` is always `"v0"`.
- Exactly one signature per request action.
- `signatures` are sorted ascending by `action_index`.
- `spend_auth_sig` is 64-byte RedPallas signature hex (128 chars, no `0x`).

Signing behavior:

- Uses roster operators over mTLS gRPC only (`grpc_endpoint` entries in config roster).
- Enforces ceremony hash pinning for all RPCs.
- Performs rerandomized FROST using per-request `(sighash, alpha, rk)`.
- Verifies aggregated signature against randomized verifying key (`rk`) before emitting output.
- Never requires spending seeds or Orchard spending keys.

Exit codes:

- `0`: success
- `1`: runtime/signing/threshold/session conflict failures
- `2`: CLI usage / input validation failures

### End-to-End Example (`ext-prepare` -> `sign-spendauth` -> `ext-finalize`)

1. Build a plan with `juno-txbuild`:

```bash
juno-txbuild send \
  --rpc-url "$RPC_URL" \
  --rpc-user "$RPC_USER" \
  --rpc-pass "$RPC_PASS" \
  --scan-url "$SCAN_URL" \
  --wallet-id "$WALLET_ID" \
  --coin-type 8135 \
  --account 0 \
  --to "$TO_UA" \
  --amount-zat 1000000 \
  --change-address "$CHANGE_UA" \
  --out ./txplan.json
```

2. Prepare external signing requests:

```bash
juno-txsign ext-prepare \
  --txplan ./txplan.json \
  --ufvk "$UFVK" \
  --out-prepared ./prepared.json \
  --out-requests ./signing_requests.v0.json
```

3. Produce spend-auth signatures from threshold DKG participants:

```bash
dkg-admin --config ./operator1-config.json sign-spendauth \
  --session-id 0x1111111111111111111111111111111111111111111111111111111111111111 \
  --requests ./signing_requests.v0.json \
  --out ./spend_auth_sigs.v0.json
```

4. Finalize signed tx:

```bash
juno-txsign ext-finalize \
  --prepared-tx ./prepared.json \
  --sigs ./spend_auth_sigs.v0.json \
  --json
```

5. Broadcast and mine via `junocash-cli` / `juno-broadcast`.

Schema files shipped in this repo:

- `api/signing_requests.v0.schema.json`
- `api/spend_auth_sigs.v0.schema.json`

## Signing Policy (`serve --sign-policy-file`)

By default a peer signs whatever the coordinator sends it. With a signing policy, every peer
checks the transaction itself before it hands out a commitment or a signature share, so a
compromised coordinator can't get a spend signed that the peers wouldn't approve.

The policy is off unless `--sign-policy-file` is passed. Without it the service behaves exactly
as before.

```bash
dkg-admin --config ./config.json serve --sign-policy-file ./sign-policy.json
```

Policy file:

```json
{
  "version": "v1",
  "ufvk": "jview1...",
  "change_address": "j1...",
  "max_fee_zat": 10000000,
  "max_spends": 200,
  "verifier_cmd": ["/usr/local/bin/withdraw-verifier", "--strict"],
  "verifier_env": { "VERIFIER_RPC_URL": "http://127.0.0.1:8545" },
  "verifier_timeout_secs": 20,
  "approval_ttl_secs": 300
}
```

- `ufvk`: the group UFVK. Its spend validating key must equal the DKG group key. This is checked
  at startup when the key package exists, and again on every approval.
- `change_address`: the only allowed change address. Must be owned by `ufvk`.
- `max_fee_zat`: default `10000000`.
- `max_spends`: max number of notes in a plan, default `200`.
- `verifier_cmd`: required. argv of an external allowlist command (no shell).
- `verifier_env`: optional extra environment for the verifier. The verifier does not inherit the
  peer's environment; it only gets `PATH` plus these variables.
- `verifier_timeout_secs`: default `20`, max `25`.
- `approval_ttl_secs`: how long an approved `(sighash, alpha)` stays signable, default `300`.
- Address/UFVK network comes from the config `network`. Unknown fields are rejected.

The coordinator passes the plan and the prepared tx next to the signing requests:

```bash
dkg-admin --config ./operator1-config.json sign-spendauth \
  --session-id 0x<64-hex> \
  --txplan ./txplan.json \
  --prepared-tx ./prepared.json \
  --requests ./signing_requests.v0.json \
  --out ./spend_auth_sigs.v0.json
```

`--txplan` and `--prepared-tx` go together. The coordinator sends them to every peer
(`ApproveSpendAuth`) before signing starts. Each peer with a policy then checks:

- the sighash recomputed from the prepared tx equals every requested sighash, and each
  request's `rk`/`alpha` matches the spend action and the group key;
- the requested spends are exactly the plan notes (decrypted with the UFVK), and the tx value
  balance equals the plan fee;
- the outputs recovered with the UFVK outgoing viewing keys are exactly the plan outputs plus
  change to `change_address`. Since our spends and the value balance are pinned, any output the
  OVK can't recover could only be funded by inputs that aren't ours;
- `change_address == policy change_address`, `fee_zat <= max_fee_zat`, `len(notes) <= max_spends`;
- the tx is on the NU6.2 branch, no `rk` repeats across actions, and the bundle has no more
  actions than the plan needs;
- the verifier command exits `0`.

The verifier gets a JSON document on stdin:

```json
{
  "version": "v1",
  "operator_id": "0x...",
  "identifier": 1,
  "ceremony_hash": "...",
  "network": "mainnet",
  "sighash": "...",
  "fee_zat": "15000",
  "change_address": "j1...",
  "change_zat": "735000",
  "spend_count": 1,
  "outputs": [{ "to_address": "j1...", "amount_zat": "250000", "memo_hex": "f600..." }],
  "signing_requests": [{ "action_index": 0, "alpha": "...", "rk": "..." }],
  "txplan": { "...": "the plan as sent by the coordinator" }
}
```

`outputs` are the non-change outputs, already checked against the transaction, with canonical
addresses and the full 512-byte memo. Any non-zero exit or timeout rejects the spend. The
verifier's whole process group is killed once it exits or times out. Its stderr (truncated to
512 chars) ends up in the rejection reason and is sent back to the coordinator, so don't write
secrets to it.

With a policy enabled, the peer only produces commitments and shares for approved
`(sighash, alpha)` pairs. That also covers the smoke RPCs, so smoke signing against a policy
peer fails with `not_approved`.

Rejections come back as gRPC `PERMISSION_DENIED` with message `policy_rejected: <code>[: detail]`
and the peer logs `sign policy rejected spend` with the reason. Codes include
`change_address_mismatch`, `fee_over_cap`, `too_many_spends`, `verifier_rejected`,
`sighash_mismatch`, `spend_set_mismatch`, `outputs_mismatch`, `value_balance_mismatch`,
`rk_mismatch`, `rk_reused`, `alpha_mismatch`, `branch_id_unsupported` and `actions_too_many`. `sign-spendauth` drops rejecting peers and fails with
`policy_rejected: need=<t> have=<n> rejections=[...]` if fewer than threshold approve.

A peer evaluates at most 4 approvals at once; beyond that it answers `RESOURCE_EXHAUSTED`
(`approvals_busy`) and the coordinator drops it for that run.

Peers without a policy answer `enforced=false`; peers running an older release answer
`UNIMPLEMENTED` and are used as before. For the policy to mean anything, at least
`max_signers - threshold + 1` peers need it.

## Destroy Local State

```bash
dkg-admin --config ./config.json destroy
```

Best-effort:

- wipes local plaintext temp files
- zeroizes in-memory secrets where applicable
