use age::secrecy::ExposeSecret;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use dkg_admin::encrypt::{kms_decrypt, kms_encrypt, EncryptError, KmsProvider};

#[test]
fn age_encrypt_decrypt_roundtrip() {
    let id = age::x25519::Identity::generate();
    let recip = id.to_public().to_string();
    let id_str = id.to_string().expose_secret().to_string();

    let pt = b"hello age";
    let ct = dkg_admin::encrypt::age_encrypt(&[recip], pt).unwrap();
    let out = dkg_admin::encrypt::age_decrypt(&id_str, &ct).unwrap();
    assert_eq!(out, pt);
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

#[tokio::test]
async fn kms_encrypt_decrypt_roundtrip_with_mock() {
    let kms = MockKmsProvider;
    let pt = b"hello kms";

    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let out = kms_encrypt("kms-key-id", pt, &kms, &mut rng).await.unwrap();

    let got = kms_decrypt(&out.encrypted_data_key, &out.nonce, &out.ciphertext, &kms)
        .await
        .unwrap();
    assert_eq!(got, pt);
}
