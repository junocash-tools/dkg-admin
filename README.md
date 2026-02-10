# dkg-admin

Operator-side daemon/CLI for participating in a RedPallas FROST DKG (Orchard spend-auth, RedPallas) and exporting an encrypted per-operator key package blob for `tss-host`.

This repo is part of the `junocash-tools` org.

## Build / Test

- `make build`
- `make test`
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
    "tls_server_key_pem_path": "./tls/server.key"
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

## Destroy Local State

```bash
dkg-admin --config ./config.json destroy
```

Best-effort:

- wipes local plaintext temp files
- zeroizes in-memory secrets where applicable
