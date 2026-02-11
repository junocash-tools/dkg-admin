use std::collections::BTreeMap;

use age::secrecy::ExposeSecret;
use base64::Engine as _;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use dkg_admin::config::{AdminConfigV1, Network, ValidatedAdminConfig};
use dkg_admin::dkg::{AdminDkg, DkgError};
use dkg_admin::envelope::{EncryptedKeyPackageEnvelopeV1, EncryptionBackendV1, KeyPackagePlaintextV1};
use dkg_admin::encrypt::{kms_decrypt, EncryptError, KmsProvider};
use dkg_admin::export::Exporter;
use dkg_admin::roster::{RosterOperatorV1, RosterV1};
use dkg_admin::{crypto, smoke, storage};

fn make_configs(tmp: &tempfile::TempDir) -> Vec<ValidatedAdminConfig> {
    let n = 5u16;
    let threshold = 3u16;

    let roster = RosterV1 {
        roster_version: 1,
        operators: (1..=n)
            .map(|i| RosterOperatorV1 {
                operator_id: format!("op{:02}", i),
                grpc_endpoint: None,
                age_recipient: None,
            })
            .collect(),
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().unwrap();

    (1..=n)
        .map(|i| {
            let cfg = AdminConfigV1 {
                config_version: 1,
                ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
                operator_id: format!("op{:02}", i),
                identifier: i,
                threshold,
                max_signers: n,
                network: Network::Regtest,
                roster: roster.clone(),
                roster_hash_hex: roster_hash_hex.clone(),
                state_dir: tmp.path().join(format!("op{:02}/state", i)),
                age_identity_file: None,
                grpc: None,
            };
            cfg.validate().unwrap()
        })
        .collect()
}

fn run_dkg(
    cfgs: &[ValidatedAdminConfig],
) -> (
    BTreeMap<u16, Vec<u8>>,
    BTreeMap<u16, BTreeMap<u16, Vec<u8>>>,
    Vec<dkg_admin::dkg::Part3Output>,
) {
    let n = cfgs[0].cfg.max_signers;

    // Round 1
    let mut round1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut seed = [0u8; 32];
        seed[0..2].copy_from_slice(&cfg.cfg.identifier.to_le_bytes());
        let rng = ChaCha20Rng::from_seed(seed);
        let out = dkg.part1(rng).unwrap();
        round1.insert(cfg.cfg.identifier, out.round1_package_bytes);
    }
    assert_eq!(round1.len(), n as usize);

    // Round 2 (gather packages by receiver)
    let mut round2_to = BTreeMap::<u16, BTreeMap<u16, Vec<u8>>>::new();
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut round1_others = round1.clone();
        round1_others.remove(&cfg.cfg.identifier);
        let out = dkg.part2(round1_others).unwrap();
        for (receiver, pkg) in out.round2_packages {
            if receiver == cfg.cfg.identifier {
                continue;
            }
            round2_to
                .entry(receiver)
                .or_default()
                .insert(cfg.cfg.identifier, pkg.package_bytes);
        }
    }
    for receiver in 1..=n {
        assert_eq!(
            round2_to.get(&receiver).unwrap().len(),
            (n - 1) as usize
        );
    }

    // Round 3
    let mut outs = Vec::with_capacity(cfgs.len());
    for cfg in cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let to_me = round2_to.get(&cfg.cfg.identifier).unwrap().clone();
        let mut round1_others = round1.clone();
        round1_others.remove(&cfg.cfg.identifier);
        outs.push(dkg.part3(round1_others, to_me).unwrap());
    }

    (round1, round2_to, outs)
}

#[test]
fn rejects_invalid_round1_package() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfgs = make_configs(&tmp);

    // Round 1
    let mut round1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in &cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut seed = [0u8; 32];
        seed[0..2].copy_from_slice(&cfg.cfg.identifier.to_le_bytes());
        let rng = ChaCha20Rng::from_seed(seed);
        let out = dkg.part1(rng).unwrap();
        round1.insert(cfg.cfg.identifier, out.round1_package_bytes);
    }

    // Corrupt one package
    let mut corrupted = round1.clone();
    let p = corrupted.get_mut(&2).unwrap();
    p[0] ^= 0x01;

    // Part2 should reject
    let dkg1 = AdminDkg::new(cfgs[0].clone());
    corrupted.remove(&1);
    assert!(dkg1.part2(corrupted).is_err());
}

#[test]
fn rejects_invalid_round2_package() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfgs = make_configs(&tmp);

    let (round1, mut round2_to, _outs) = run_dkg(&cfgs);

    // Corrupt a round2 package destined for participant 1 from sender 2.
    let p = round2_to.get_mut(&1).unwrap().get_mut(&2).unwrap();
    p[0] ^= 0x01;

    let dkg1 = AdminDkg::new(cfgs[0].clone());
    let to_me = round2_to.get(&1).unwrap().clone();
    let mut round1_others = round1.clone();
    round1_others.remove(&1);
    assert!(dkg1.part3(round1_others, to_me).is_err());
}

#[test]
fn part2_part3_idempotent_with_input_binding() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfgs = make_configs(&tmp);

    // Round 1
    let mut round1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in &cfgs {
        let dkg = AdminDkg::new(cfg.clone());
        let mut seed = [0u8; 32];
        seed[0..2].copy_from_slice(&cfg.cfg.identifier.to_le_bytes());
        let rng = ChaCha20Rng::from_seed(seed);
        let out = dkg.part1(rng).unwrap();
        round1.insert(cfg.cfg.identifier, out.round1_package_bytes);
    }

    // Participant 1 part2 first run.
    let dkg1 = AdminDkg::new(cfgs[0].clone());
    let mut round1_for_1 = round1.clone();
    round1_for_1.remove(&1);
    let part2_a = dkg1.part2(round1_for_1.clone()).unwrap();
    let part2_b = dkg1.part2(round1_for_1.clone()).unwrap();
    assert_eq!(part2_a.round2_packages.len(), part2_b.round2_packages.len());

    // Same phase, different input must fail.
    let mut round1_modified = round1_for_1.clone();
    let p = round1_modified.get_mut(&2).unwrap();
    p[0] ^= 0x01;
    let err = dkg1.part2(round1_modified).unwrap_err();
    assert!(matches!(err, DkgError::Part2InputMismatch));

    // Gather valid round2 for participant 1 and run part3 twice.
    let mut round2_to_1 = BTreeMap::<u16, Vec<u8>>::new();
    for cfg in &cfgs {
        if cfg.cfg.identifier == 1 {
            continue;
        }
        let dkg = AdminDkg::new(cfg.clone());
        let mut round1_others = round1.clone();
        round1_others.remove(&cfg.cfg.identifier);
        let out = dkg.part2(round1_others).unwrap();
        let pkg = out.round2_packages.get(&1).unwrap().package_bytes.clone();
        round2_to_1.insert(cfg.cfg.identifier, pkg);
    }

    let mut round1_for_1b = round1.clone();
    round1_for_1b.remove(&1);
    let part3_a = dkg1.part3(round1_for_1b.clone(), round2_to_1.clone()).unwrap();
    let part3_b = dkg1.part3(round1_for_1b.clone(), round2_to_1.clone()).unwrap();
    assert_eq!(part3_a.public_key_package_hash, part3_b.public_key_package_hash);
    assert_eq!(part3_a.ak_bytes, part3_b.ak_bytes);

    // Different input after first success must fail.
    let mut round2_bad = round2_to_1.clone();
    let p = round2_bad.get_mut(&2).unwrap();
    p[0] ^= 0x01;
    let err = dkg1.part3(round1_for_1b, round2_bad).unwrap_err();
    assert!(matches!(err, DkgError::Part3InputMismatch));
}

struct MockKmsProvider;

#[async_trait::async_trait]
impl KmsProvider for MockKmsProvider {
    async fn encrypt(&self, _key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let mut out = b"mockkms".to_vec();
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptError> {
        if ciphertext.len() < 7 || &ciphertext[..7] != b"mockkms" {
            return Err(EncryptError::AwsKmsDecryptFailed(
                "mockkms_invalid_ciphertext".to_string(),
            ));
        }
        Ok(ciphertext[7..].to_vec())
    }
}

fn randomizer_bytes(alpha: Option<u8>) -> Vec<u8> {
    match alpha {
        None => vec![],
        Some(x) => {
            let mut b = vec![0u8; 32];
            b[0] = x;
            b
        }
    }
}

#[tokio::test]
async fn full_dkg_smoke_signing_and_export() {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfgs = make_configs(&tmp);

    let (_round1, _round2_to, outs) = run_dkg(&cfgs);

    // All participants must agree on pk hash and ak.
    let expected_hash = outs[0].public_key_package_hash;
    let expected_ak = outs[0].ak_bytes;
    for o in &outs {
        assert_eq!(o.public_key_package_hash, expected_hash);
        assert_eq!(o.ak_bytes, expected_ak);
        assert!(crypto::is_canonical_ak_bytes(&o.ak_bytes));
    }

    // Smoke signing: standard and randomized.
    let message = b"junocash_dkg_smoke_v1";

    // Load public key package from operator 1.
    let pkp_bytes = storage::read(&cfgs[0].cfg.state_dir.join("public_key_package.bin")).unwrap();
    let pubkeys = reddsa::frost::redpallas::keys::PublicKeyPackage::deserialize(&pkp_bytes).unwrap();

    for alpha in [None, Some(1u8)] {
        let alpha_bytes = randomizer_bytes(alpha);

        // Round 1 commitments
        let mut commitments_by_signer = BTreeMap::<u16, Vec<u8>>::new();
        let mut key_packages = BTreeMap::<u16, reddsa::frost::redpallas::keys::KeyPackage>::new();
        for id in 1u16..=3u16 {
            let kp_bytes = storage::read(&cfgs[(id - 1) as usize].cfg.state_dir.join("key_package.bin")).unwrap();
            let key_package = reddsa::frost::redpallas::keys::KeyPackage::deserialize(&kp_bytes).unwrap();
            key_packages.insert(id, key_package.clone());

            let mut seed = [0u8; 32];
            seed[0..2].copy_from_slice(&id.to_le_bytes());
            let mut rng = ChaCha20Rng::from_seed(seed);

            let commitments = smoke::smoke_commit(
                &cfgs[(id - 1) as usize].cfg.state_dir,
                &key_package,
                message,
                &alpha_bytes,
                &mut rng,
            )
            .unwrap();
            commitments_by_signer.insert(id, commitments);
        }

        let signing_package_bytes =
            smoke::make_signing_package(commitments_by_signer.clone(), message).unwrap();
        let signing_package =
            reddsa::frost::redpallas::SigningPackage::deserialize(&signing_package_bytes).unwrap();

        // Round 2 shares
        let mut sig_shares = BTreeMap::new();
        for id in 1u16..=3u16 {
            let key_package = key_packages.get(&id).unwrap();
            let sig_share_bytes = smoke::smoke_sign_share(
                &cfgs[(id - 1) as usize].cfg.state_dir,
                key_package,
                &signing_package_bytes,
                &alpha_bytes,
            )
            .unwrap();
            let sig_share =
                reddsa::frost::redpallas::round2::SignatureShare::deserialize(&sig_share_bytes)
                    .unwrap();
            let ident: reddsa::frost::redpallas::Identifier = id.try_into().unwrap();
            sig_shares.insert(ident, sig_share);
        }

        let randomizer = if alpha_bytes.is_empty() {
            reddsa::frost::redpallas::Randomizer::deserialize(&[0u8; 32]).unwrap()
        } else {
            reddsa::frost::redpallas::Randomizer::deserialize(&alpha_bytes).unwrap()
        };
        let randomized_params =
            reddsa::frost::redpallas::RandomizedParams::from_randomizer(pubkeys.verifying_key(), randomizer);

        let sig = reddsa::frost::redpallas::aggregate(
            &signing_package,
            &sig_shares,
            &pubkeys,
            &randomized_params,
        )
        .unwrap();

        if alpha.is_none() {
            pubkeys.verifying_key().verify(message, &sig).unwrap();
        } else {
            randomized_params
                .randomized_verifying_key()
                .verify(message, &sig)
                .unwrap();
        }
    }

    // Export encryption: age
    let exporter = Exporter::new(cfgs[0].clone());
    let id = age::x25519::Identity::generate();
    let recip = id.to_public().to_string();
    let id_str = id.to_string().expose_secret().to_string();

    let out_path = tmp.path().join("keypackage.age.json");
    let _receipt = exporter
        .export_to_file_age(&vec![recip.clone()], &out_path)
        .await
        .unwrap();

    let blob_bytes = storage::read(&out_path).unwrap();
    let env: EncryptedKeyPackageEnvelopeV1 = serde_json::from_slice(&blob_bytes).unwrap();
    assert_eq!(env.envelope_version, dkg_admin::envelope::ENVELOPE_VERSION);
    match &env.backend {
        EncryptionBackendV1::Age { recipients } => assert_eq!(recipients, &vec![recip.clone()]),
        _ => panic!("expected age backend"),
    }

    let ct = base64::engine::general_purpose::STANDARD
        .decode(&env.ciphertext_b64)
        .unwrap();
    let pt = dkg_admin::encrypt::age_decrypt(&id_str, &ct).unwrap();
    let plain: KeyPackagePlaintextV1 = serde_json::from_slice(&pt).unwrap();
    assert_eq!(plain.operator_id, cfgs[0].cfg.operator_id);
    assert_eq!(plain.identifier, cfgs[0].cfg.identifier);
    assert_eq!(plain.public_key_package_hash_hex, hex::encode(expected_hash));

    // Export encryption: KMS (mocked)
    let kms = MockKmsProvider;
    let out_path = tmp.path().join("keypackage.kms.json");
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let _receipt = exporter
        .export_to_file_kms(&kms, "kms-key-id", &out_path, &mut rng)
        .await
        .unwrap();

    let blob_bytes = storage::read(&out_path).unwrap();
    let env: EncryptedKeyPackageEnvelopeV1 = serde_json::from_slice(&blob_bytes).unwrap();
    let (encrypted_data_key, nonce) = match &env.backend {
        EncryptionBackendV1::AwsKms {
            encrypted_data_key_b64,
            nonce_b64,
            ..
        } => {
            let dek = base64::engine::general_purpose::STANDARD
                .decode(encrypted_data_key_b64)
                .unwrap();
            let nonce_vec = base64::engine::general_purpose::STANDARD.decode(nonce_b64).unwrap();
            let nonce: [u8; 12] = nonce_vec.as_slice().try_into().unwrap();
            (dek, nonce)
        }
        _ => panic!("expected kms backend"),
    };
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&env.ciphertext_b64)
        .unwrap();
    let pt = kms_decrypt(&encrypted_data_key, &nonce, &ciphertext, &kms)
        .await
        .unwrap();
    let plain: KeyPackagePlaintextV1 = serde_json::from_slice(&pt).unwrap();
    assert_eq!(plain.operator_id, cfgs[0].cfg.operator_id);
    assert_eq!(plain.identifier, cfgs[0].cfg.identifier);
    assert_eq!(plain.public_key_package_hash_hex, hex::encode(expected_hash));
}
