//! Secrets vault — wraps tenant data-encryption keys under an RSA master key.
use rsa::{RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

/// Generate the RSA-3072 master key that wraps all tenant DEKs.
pub fn master_key() -> RsaPrivateKey {
    let mut rng = OsRng;
    RsaPrivateKey::new(&mut rng, 3072).expect("failed to generate master key")
}
