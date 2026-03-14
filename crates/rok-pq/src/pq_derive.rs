use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use rok_core::derive::derive_pq_key_seed;
use rok_core::keys::scope::Scope;

use crate::kem::PqKeyPair;

/// Derive an ML-KEM-768 keypair deterministically from a read key secret and scope.
///
/// Uses HKDF to derive a seed, then seeds a ChaCha20Rng for deterministic
/// ML-KEM key generation. The same read secret + scope always produces
/// the same keypair, so both encryptor and decryptor can independently
/// derive matching keys.
pub fn derive_pq_keypair(read_secret: &[u8; 32], scope: &Scope) -> PqKeyPair {
    let seed = derive_pq_key_seed(read_secret, scope);
    let mut rng = ChaCha20Rng::from_seed(seed);
    PqKeyPair::generate(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_pq_derivation() {
        let secret = [42u8; 32];
        let scope = Scope::new("/finance").unwrap();

        let kp1 = derive_pq_keypair(&secret, &scope);
        let kp2 = derive_pq_keypair(&secret, &scope);

        // Same secret + scope must produce the same encapsulation key
        assert_eq!(
            kp1.encapsulation_key(),
            kp2.encapsulation_key(),
            "deterministic derivation must produce identical encapsulation keys"
        );
    }

    #[test]
    fn test_different_scopes_different_pq_keys() {
        let secret = [42u8; 32];
        let finance = Scope::new("/finance").unwrap();
        let legal = Scope::new("/legal").unwrap();

        let kp_finance = derive_pq_keypair(&secret, &finance);
        let kp_legal = derive_pq_keypair(&secret, &legal);

        assert_ne!(
            kp_finance.encapsulation_key(),
            kp_legal.encapsulation_key(),
            "different scopes must produce different PQ keys"
        );
    }
}
