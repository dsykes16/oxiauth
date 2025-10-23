use openssl::{
    bn::BigNum,
    ec::{
        EcKey,
        EcKeyRef,
    },
    ecdsa::EcdsaSig,
    hash::{
        Hasher,
        MessageDigest,
    },
    memcmp,
    pkey::{
        HasPublic,
        PKey,
        PKeyRef,
    },
    sign::{
        Signer,
        Verifier,
    },
};

use crate::{
    Algorithm,
    crypto::openssl::{
        HmacKey,
        ec_curve_alg,
        map_pkey_alg,
    },
    error::JwtError,
    validation::VerificationKey,
};

impl VerificationKey for HmacKey {
    fn alg(&self) -> Option<Algorithm> {
        Some(self.alg)
    }
    fn verify(&self, msg: &[u8], asig: &[u8]) -> Result<(), JwtError> {
        let mut signer = Signer::new(self.digest(), &self.key).map_err(|_| JwtError::KeyError)?;
        signer.update(msg).map_err(|_| JwtError::InvalidSignature)?;
        let csig = signer
            .sign_to_vec()
            .map_err(|_| JwtError::InvalidSignature)?;
        if csig.len() == asig.len() && memcmp::eq(&csig, asig) {
            Ok(())
        } else {
            Err(JwtError::InvalidSignature)
        }
    }
}

impl<T> VerificationKey for PKey<T>
where
    T: HasPublic,
{
    fn alg(&self) -> Option<Algorithm> {
        map_pkey_alg(self)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        match self.alg().ok_or(JwtError::UnsupportedAlgorithm)? {
            Algorithm::RS256 | Algorithm::PS256 => {
                verify_with_digest(self, MessageDigest::sha256(), message, signature)
            }
            Algorithm::RS384 | Algorithm::PS384 => {
                verify_with_digest(self, MessageDigest::sha384(), message, signature)
            }
            Algorithm::RS512 | Algorithm::PS512 => {
                verify_with_digest(self, MessageDigest::sha512(), message, signature)
            }
            Algorithm::ES256 | Algorithm::ES256K | Algorithm::ES384 | Algorithm::ES512 => {
                let eckey = try_pkey_to_eckey(self)?;
                eckey.verify(message, signature)
            }
            Algorithm::EdDSA | Algorithm::Ed448 => verify_ed(self, message, signature),
            // TODO: impl when ML_DSA is available on rust-openssl
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 |
            // HMAC requires `HasPrivate` trait, which is at odds with all other algos.
            // OpenSSL recommends using `EVP_MAC` for HMAC/CMAC and not PKey, but rust-openssl
            // doesn't expose that. Until rust-openssl does so, the best we can do here is
            // offer a wrapper for Hmac PKeys. See [`HmacKey`]
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                unreachable!("VerificationKey::alg should return `None` if any algorithm is unsupported")
            }
        }
    }
}

impl<T> VerificationKey for EcKeyRef<T>
where
    T: HasPublic,
{
    fn alg(&self) -> Option<Algorithm> {
        ec_curve_alg(self)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        match self.alg().ok_or(JwtError::UnsupportedAlgorithm)? {
            Algorithm::ES256 | Algorithm::ES256K => {
                verify_ecdsa_with_digest(self, MessageDigest::sha256(), message, signature)
            }
            Algorithm::ES384 => {
                verify_ecdsa_with_digest(self, MessageDigest::sha384(), message, signature)
            }
            Algorithm::ES512 => {
                verify_ecdsa_with_digest(self, MessageDigest::sha512(), message, signature)
            }
            // SAFETY: [`ec_curve_alg`] only returns ES256, E256K, ES384, or ES512.
            _ => unreachable!("all alg variants returned by 'ec_curve_alg' should be covered"),
        }
    }
}

fn verify_ed<T>(key: &PKeyRef<T>, message: &[u8], signature: &[u8]) -> Result<(), JwtError>
where
    T: HasPublic,
{
    let mut verifier = Verifier::new_without_digest(key).map_err(|_| JwtError::KeyError)?;
    if verifier
        .verify_oneshot(signature, message)
        .map_err(|_| JwtError::InvalidSignature)?
    {
        Ok(())
    } else {
        Err(JwtError::InvalidSignature)
    }
}

fn verify_with_digest<T>(
    key: &PKeyRef<T>,
    digest: MessageDigest,
    message: &[u8],
    signature: &[u8],
) -> Result<(), JwtError>
where
    T: HasPublic,
{
    let mut verifier = Verifier::new(digest, key).map_err(|_| JwtError::KeyError)?;
    verifier.update(message).map_err(|_| JwtError::KeyError)?;
    if verifier
        .verify(signature)
        .map_err(|_| JwtError::InvalidSignature)?
    {
        Ok(())
    } else {
        Err(JwtError::InvalidSignature)
    }
}

fn try_pkey_to_eckey<T>(key: &PKeyRef<T>) -> Result<EcKey<T>, JwtError> {
    key.ec_key().map_err(|_| JwtError::UnsupportedAlgorithm)
}

#[allow(clippy::expect_used)]
fn verify_ecdsa_with_digest<T>(
    key: &EcKeyRef<T>,
    digest: MessageDigest,
    message: &[u8],
    signature: &[u8],
) -> Result<(), JwtError>
where
    T: HasPublic,
{
    let sp = key.group().order_bits().div_ceil(8) as usize;
    if signature.len() != sp * 2 {
        return Err(JwtError::InvalidSignature);
    }
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&signature[0..sp]).map_err(|_| JwtError::InvalidSignature)?,
        BigNum::from_slice(&signature[sp..]).map_err(|_| JwtError::InvalidSignature)?,
    )
    .map_err(|_| JwtError::InvalidSignature)?;

    let mut digest = Hasher::new(digest).expect("instantiating openssl hasher should work");
    // SAFETY: `update` should only return an err if the digest is in the `squeeze` state,
    // or maybe in the `finalized` state; in this case we're always working with a new
    // digest which should be in the `initialised` state.
    digest
        .update(message)
        .expect("calculating digest with openssl should always work");
    let digest = digest
        .finish()
        .expect("finishing digest with openssl should always work");

    if sig
        .verify(&digest, key)
        .map_err(|_| JwtError::InvalidSignature)?
    {
        Ok(())
    } else {
        Err(JwtError::InvalidSignature)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use openssl::{
        ec::{
            EcGroup,
            EcKey,
        },
        nid::Nid,
        pkey::PKey,
        rsa::Rsa,
        sign::Signer,
    };

    use crate::{
        Algorithm,
        error::JwtError,
        validation::VerificationKey,
    };

    #[test]
    fn ecdsa_with_undersized_signature() {
        let data = b"hello world";
        let sig = b"not-a-real-sig";
        let keypair = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP521R1).unwrap()).unwrap();
        let keypair = PKey::from_ec_key(keypair).unwrap();
        let err = keypair.verify(data, sig).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn ecdsa_with_oversized_signature() {
        let keypair = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP521R1).unwrap()).unwrap();
        let keypair = PKey::from_ec_key(keypair).unwrap();

        let data = b"hello world";
        let sig = [b'\xFF'; 133];
        let err = keypair.verify(data, &sig).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn ecdsa_with_right_size_but_invalid_sig() {
        let keypair = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP521R1).unwrap()).unwrap();
        let keypair = PKey::from_ec_key(keypair).unwrap();

        let data = b"hello world";
        let sig = [b'\xFF'; 132];
        let err = keypair.verify(data, &sig).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);

        let data = b"hello world";
        let sig = [b'\x00'; 132];
        let err = keypair.verify(data, &sig).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn ed25519() {
        let keypair = PKey::generate_ed25519().unwrap();
        assert_eq!(keypair.alg().unwrap(), Algorithm::EdDSA);

        let data = b"eyJhbGciOiJFUzI1NiJ9.e30";
        let bad_data = b"ayJhbGciOiJFUzI1NiJ9.e31";

        let mut signer = Signer::new_without_digest(&keypair).unwrap();
        let signature = signer.sign_oneshot_to_vec(data).unwrap();

        keypair.verify(data, &signature).unwrap();

        let err = keypair.verify(bad_data, &signature).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn ed448() {
        let keypair = PKey::generate_ed448().unwrap();
        assert_eq!(keypair.alg().unwrap(), Algorithm::Ed448);

        let data = b"eyJhbGciOiJFUzI1NiJ9.e30";
        let bad_data = b"ayJhbGciOiJFUzI1NiJ9.e31";

        let mut signer = Signer::new_without_digest(&keypair).unwrap();
        let signature = signer.sign_oneshot_to_vec(data).unwrap();

        keypair.verify(data, &signature).unwrap();

        let err = keypair.verify(bad_data, &signature).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn unsupported_ec_curve() {
        let keypair = EcKey::generate(&EcGroup::from_curve_name(Nid::SECT283R1).unwrap()).unwrap();
        let keypair = PKey::from_ec_key(keypair).unwrap();
        let eckey = keypair.ec_key().unwrap();

        assert_eq!(keypair.alg(), None);
        assert_eq!(eckey.alg(), None);

        let err = keypair.verify(b"", b"").unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);

        let err = eckey.verify(b"", b"").unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn unsupported_rsa_len() {
        let keypair = Rsa::generate(1024).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();

        assert_eq!(keypair.alg(), None);

        let err = keypair.verify(b"", b"").unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn hmac_unsupported() {
        let keypair = PKey::hmac(&[b'a', 32]).unwrap();

        assert_eq!(keypair.alg(), None);

        let err = keypair.verify(b"", b"").unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }
}
