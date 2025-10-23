use aws_lc_rs::{
    hmac::{
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        Key as HmacKey,
        verify as verify_hmac,
    },
    rsa::PublicKey as RsaPublicKey,
    signature::{
        ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P256K1_SHA256_FIXED,
        ECDSA_P256K1_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED,
        ECDSA_P384_SHA384_FIXED_SIGNING,
        ECDSA_P521_SHA512_FIXED,
        ECDSA_P521_SHA512_FIXED_SIGNING,
        ED25519,
        EcdsaKeyPair,
        Ed25519KeyPair,
        Ed25519PublicKey,
        KeyPair,
        ParsedPublicKey,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256,
        RSA_PSS_2048_8192_SHA384,
        RSA_PSS_2048_8192_SHA512,
    },
    unstable::signature::{
        ML_DSA_44,
        ML_DSA_44_SIGNING,
        ML_DSA_65,
        ML_DSA_65_SIGNING,
        ML_DSA_87,
        ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
};

use crate::{
    Algorithm,
    JwtError,
    validation::VerificationKey,
};

#[derive(Debug)]
enum KeyType {
    Asymmetric(ParsedPublicKey),
    Hmac(Box<HmacKey>),
}
impl From<ParsedPublicKey> for KeyType {
    fn from(key: ParsedPublicKey) -> Self {
        Self::Asymmetric(key)
    }
}
impl From<HmacKey> for KeyType {
    fn from(key: HmacKey) -> Self {
        Self::Hmac(Box::new(key))
    }
}

fn map_pkey_alg(key: &ParsedPublicKey) -> Option<Algorithm> {
    let kalg = key.algorithm();
    if std::ptr::addr_eq(kalg, &raw const RSA_PKCS1_2048_8192_SHA256) {
        Some(Algorithm::RS256)
    } else if std::ptr::addr_eq(kalg, &raw const RSA_PKCS1_2048_8192_SHA384) {
        Some(Algorithm::RS384)
    } else if std::ptr::addr_eq(kalg, &raw const RSA_PKCS1_2048_8192_SHA512) {
        Some(Algorithm::RS512)
    } else if std::ptr::addr_eq(kalg, &raw const RSA_PSS_2048_8192_SHA256) {
        Some(Algorithm::PS256)
    } else if std::ptr::addr_eq(kalg, &raw const RSA_PSS_2048_8192_SHA384) {
        Some(Algorithm::PS384)
    } else if std::ptr::addr_eq(kalg, &raw const RSA_PSS_2048_8192_SHA512) {
        Some(Algorithm::PS512)
    } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P256_SHA256_FIXED) {
        Some(Algorithm::ES256)
    } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P256K1_SHA256_FIXED) {
        Some(Algorithm::ES256K)
    } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P384_SHA384_FIXED) {
        Some(Algorithm::ES384)
    } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P521_SHA512_FIXED) {
        Some(Algorithm::ES512)
    } else if std::ptr::addr_eq(kalg, &raw const ED25519) {
        Some(Algorithm::EdDSA)
    } else if std::ptr::addr_eq(kalg, &raw const ML_DSA_44) {
        Some(Algorithm::MlDsa44)
    } else if std::ptr::addr_eq(kalg, &raw const ML_DSA_65) {
        Some(Algorithm::MlDsa65)
    } else if std::ptr::addr_eq(kalg, &raw const ML_DSA_87) {
        Some(Algorithm::MlDsa87)
    } else {
        None
    }
}

fn map_hkey_alg(key: &HmacKey) -> Option<Algorithm> {
    if key.algorithm() == HMAC_SHA256 {
        Some(Algorithm::HS256)
    } else if key.algorithm() == HMAC_SHA384 {
        Some(Algorithm::HS384)
    } else if key.algorithm() == HMAC_SHA512 {
        Some(Algorithm::HS512)
    } else {
        None
    }
}

impl VerificationKey for ParsedPublicKey {
    fn alg(&self) -> Option<Algorithm> {
        map_pkey_alg(self)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        self.verify_sig(message, signature)
            .map_err(|_| JwtError::InvalidSignature)
    }
}

impl VerificationKey for HmacKey {
    fn alg(&self) -> Option<Algorithm> {
        map_hkey_alg(self)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        verify_hmac(self, message, signature).map_err(|_| JwtError::InvalidSignature)
    }
}

/// Wrapper around a [`ParsedPublicKey`] or [`HmacKey`] that parses the key algorithm
/// to a JWT algorithm at initialization to permit raising unsupported algorithm errors
/// as early in the process as possible and avoid the overhead of converting the raw key
/// algorithm to a JWT algorithm with each verification operation.
///
/// # Examples
///
/// ```rust
/// let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
/// let alg = &RSA_PKCS1_2048_8192_SHA256;
///
/// let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
/// let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
/// assert_eq!(key.alg().unwrap(), Algorithm::RS256);
/// ```
#[derive(Debug)]
pub struct AwsLcVerificationKey {
    alg: Algorithm,
    key: KeyType,
}
impl AwsLcVerificationKey {
    /// Creates a new [`AwsLcVerificationKey`] from a [`RsaPublicKey`] ref
    ///
    /// # Errors
    ///
    /// [`JwtError::UnsupportedAlgorithm`] when `key` is not a 2048, 3072, or 4096-bit
    /// RSA key
    ///
    /// # Panics
    ///
    /// If the [`RsaPublicKey`] can't be parsed, which should never happen
    pub fn from_rsa_public_key(key: &RsaPublicKey, pss: bool) -> Result<Self, JwtError> {
        let res = match (key.modulus_len(), pss) {
            (256, false) => Ok((Algorithm::RS256, &RSA_PKCS1_2048_8192_SHA256)),
            (384, false) => Ok((Algorithm::RS384, &RSA_PKCS1_2048_8192_SHA384)),
            (512, false) => Ok((Algorithm::RS512, &RSA_PKCS1_2048_8192_SHA512)),
            (256, true) => Ok((Algorithm::PS256, &RSA_PSS_2048_8192_SHA256)),
            (384, true) => Ok((Algorithm::PS384, &RSA_PSS_2048_8192_SHA384)),
            (512, true) => Ok((Algorithm::PS512, &RSA_PSS_2048_8192_SHA512)),
            _ => Err(JwtError::UnsupportedAlgorithm),
        };
        let (_, key_alg) = res?;
        #[allow(clippy::expect_used)]
        ParsedPublicKey::new(key_alg, key.as_ref())
            .expect("RsaPublicKey should always yield a valid ParsedPublicKey")
            .try_into()
    }
}
impl TryFrom<ParsedPublicKey> for AwsLcVerificationKey {
    type Error = JwtError;
    fn try_from(key: ParsedPublicKey) -> Result<Self, Self::Error> {
        let alg = map_pkey_alg(&key).ok_or(JwtError::UnsupportedAlgorithm)?;
        let key = key.into();
        Ok(Self { alg, key })
    }
}
impl TryFrom<HmacKey> for AwsLcVerificationKey {
    type Error = JwtError;
    fn try_from(key: HmacKey) -> Result<Self, Self::Error> {
        let alg = map_hkey_alg(&key).ok_or(JwtError::UnsupportedAlgorithm)?;
        let key = key.into();
        Ok(Self { alg, key })
    }
}
impl TryFrom<&EcdsaKeyPair> for AwsLcVerificationKey {
    type Error = JwtError;
    fn try_from(key: &EcdsaKeyPair) -> Result<Self, Self::Error> {
        let alg = if key.algorithm().eq(&ECDSA_P256_SHA256_FIXED_SIGNING) {
            Ok(&ECDSA_P256_SHA256_FIXED)
        } else if key.algorithm().eq(&ECDSA_P256K1_SHA256_FIXED_SIGNING) {
            Ok(&ECDSA_P256K1_SHA256_FIXED)
        } else if key.algorithm().eq(&ECDSA_P384_SHA384_FIXED_SIGNING) {
            Ok(&ECDSA_P384_SHA384_FIXED)
        } else if key.algorithm().eq(&ECDSA_P521_SHA512_FIXED_SIGNING) {
            Ok(&ECDSA_P521_SHA512_FIXED)
        } else {
            Err(JwtError::UnsupportedAlgorithm)
        }?;
        #[allow(clippy::expect_used)]
        ParsedPublicKey::new(alg, key.public_key().as_ref())
            .expect("EcdsaKeyPair should always yield a valid public key")
            .try_into()
    }
}
impl TryFrom<&PqdsaKeyPair> for AwsLcVerificationKey {
    type Error = JwtError;
    fn try_from(key: &PqdsaKeyPair) -> Result<Self, Self::Error> {
        let kalg = key.algorithm();
        let alg = if kalg.eq(&ML_DSA_44_SIGNING) {
            Ok(&ML_DSA_44)
        } else if kalg.eq(&ML_DSA_65_SIGNING) {
            Ok(&ML_DSA_65)
        } else if kalg.eq(&ML_DSA_87_SIGNING) {
            Ok(&ML_DSA_87)
        } else {
            // this is unreachable as of aws-lc-rs v1.14.1 as all currently supported Pqdsa algs are covered above
            Err(JwtError::UnsupportedAlgorithm)
        }?;
        #[allow(clippy::expect_used)]
        ParsedPublicKey::new(alg, key.public_key().as_ref())
            .expect("PqdsaKeyPair should always yield a valid public key")
            .try_into()
    }
}
impl From<&Ed25519PublicKey> for AwsLcVerificationKey {
    fn from(key: &Ed25519PublicKey) -> Self {
        Self {
            alg: Algorithm::EdDSA,
            #[allow(clippy::expect_used)]
            key: ParsedPublicKey::new(&ED25519, key.as_ref())
                .expect("Ed25519KeyPair should always result in a valid ParsedPublicKey")
                .into(),
        }
    }
}
impl From<&Ed25519KeyPair> for AwsLcVerificationKey {
    fn from(key: &Ed25519KeyPair) -> Self {
        key.public_key().into()
    }
}
impl VerificationKey for AwsLcVerificationKey {
    fn alg(&self) -> Option<Algorithm> {
        Some(self.alg)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        match &self.key {
            KeyType::Asymmetric(key) => key.verify_sig(message, signature),
            KeyType::Hmac(key) => verify_hmac(key, message, signature),
        }
        .map_err(|_| JwtError::InvalidSignature)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use aws_lc_rs::{
        hmac::{
            HMAC_SHA224,
            HMAC_SHA256,
            Key as HmacKey,
        },
        rand::SystemRandom,
        rsa::KeySize,
        signature::{
            ECDSA_P256_SHA256_FIXED,
            ECDSA_P256_SHA256_FIXED_SIGNING,
            ECDSA_P256K1_SHA256_FIXED,
            ECDSA_P256K1_SHA256_FIXED_SIGNING,
            ECDSA_P384_SHA384_FIXED,
            ECDSA_P384_SHA384_FIXED_SIGNING,
            ECDSA_P521_SHA256_FIXED_SIGNING,
            ECDSA_P521_SHA512_FIXED,
            ECDSA_P521_SHA512_FIXED_SIGNING,
            ED25519,
            EcdsaKeyPair,
            Ed25519KeyPair,
            KeyPair,
            ParsedPublicKey,
            RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512,
            RSA_PSS_2048_8192_SHA256,
            RSA_PSS_2048_8192_SHA384,
            RSA_PSS_2048_8192_SHA512,
            RsaKeyPair,
        },
        unstable::signature::{
            ML_DSA_44,
            ML_DSA_44_SIGNING,
            ML_DSA_65,
            ML_DSA_65_SIGNING,
            ML_DSA_87,
            ML_DSA_87_SIGNING,
            PqdsaKeyPair,
        },
    };

    use super::AwsLcVerificationKey;
    use crate::{
        Algorithm,
        JwtError,
        validation::VerificationKey,
    };

    #[test]
    fn parsed_key_to_rs256() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let alg = &RSA_PKCS1_2048_8192_SHA256;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::RS256);
    }

    #[test]
    fn parsed_key_to_rs384() {
        let key = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();
        let alg = &RSA_PKCS1_2048_8192_SHA384;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::RS384);
    }

    #[test]
    fn parsed_key_to_rs512() {
        let key = RsaKeyPair::generate(KeySize::Rsa4096).unwrap();
        let alg = &RSA_PKCS1_2048_8192_SHA512;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::RS512);
    }

    #[test]
    fn parsed_key_to_ps256() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let alg = &RSA_PSS_2048_8192_SHA256;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::PS256);
    }

    #[test]
    fn parsed_key_to_ps384() {
        let key = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();
        let alg = &RSA_PSS_2048_8192_SHA384;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::PS384);
    }

    #[test]
    fn parsed_key_to_ps512() {
        let key = RsaKeyPair::generate(KeySize::Rsa4096).unwrap();
        let alg = &RSA_PSS_2048_8192_SHA512;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::PS512);
    }

    #[test]
    fn parsed_key_rsa_sha1_unsupported() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let alg = &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY;

        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let err = AwsLcVerificationKey::try_from(parsed_key).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn parsed_key_to_es256() {
        let alg = &ECDSA_P256_SHA256_FIXED;
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES256);
    }

    #[test]
    fn parsed_key_to_es256k() {
        let alg = &ECDSA_P256K1_SHA256_FIXED;
        let key = EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES256K);
    }

    #[test]
    fn parsed_key_to_es384() {
        let alg = &ECDSA_P384_SHA384_FIXED;
        let key = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES384);
    }

    #[test]
    fn parsed_key_to_es512() {
        let alg = &ECDSA_P521_SHA512_FIXED;
        let key = EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES512);
    }

    #[test]
    fn parsed_key_to_mldsa44() {
        let alg = &ML_DSA_44;
        let key = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa44);
    }

    #[test]
    fn parsed_key_to_mldsa65() {
        let alg = &ML_DSA_65;
        let key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa65);
    }

    #[test]
    fn parsed_key_to_mldsa87() {
        let alg = &ML_DSA_87;
        let key = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        let parsed_key = ParsedPublicKey::new(alg, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa87);
    }
    #[test]
    fn parsed_key_to_ed25519() {
        let key = Ed25519KeyPair::generate().unwrap();
        let parsed_key = ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap();
        let key = AwsLcVerificationKey::try_from(parsed_key).unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::EdDSA);
    }

    #[test]
    fn ecdsa_keypair_try_into() {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES256);

        let key = EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES256K);

        let key = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES384);

        let key = EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::ES512);

        let key = EcdsaKeyPair::generate(&ECDSA_P521_SHA256_FIXED_SIGNING).unwrap();
        let err = AwsLcVerificationKey::try_from(&key).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn ed25519_keypair_into() {
        let key = Ed25519KeyPair::generate().unwrap();
        let key: AwsLcVerificationKey = (&key).into();
        assert_eq!(key.alg(), Some(Algorithm::EdDSA));
    }

    #[test]
    fn ed25519_public_key_into() {
        let key = Ed25519KeyPair::generate().unwrap();
        let key: AwsLcVerificationKey = (&key).into();
        assert_eq!(key.alg().unwrap(), Algorithm::EdDSA);
    }

    #[test]
    fn mldsa44_public_key_into() {
        let key = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa44);
    }

    #[test]
    fn mldsa65_public_key_into() {
        let key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa65);
    }

    #[test]
    fn mldsa87_public_key_into() {
        let key = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        let key: AwsLcVerificationKey = (&key).try_into().unwrap();
        assert_eq!(key.alg().unwrap(), Algorithm::MlDsa87);
    }

    #[test]
    fn hmac224_unsupported() {
        let key = HmacKey::generate(HMAC_SHA224, &SystemRandom::new()).unwrap();
        let err = AwsLcVerificationKey::try_from(key).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    #[ignore = "rsa 8192 keygen is slow"]
    fn rsa_8192_unsupported() {
        let key = RsaKeyPair::generate(KeySize::Rsa8192).unwrap();

        let err = AwsLcVerificationKey::from_rsa_public_key(key.public_key(), false).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn verify_err_mapped_to_jwt_error_invalid_signature() {
        let key = HmacKey::new(HMAC_SHA256, b"a-string-secret-at-least-256-bits-long");
        let key: AwsLcVerificationKey = key.try_into().unwrap();
        let err = key.verify(b"bad-data", b"bad-sig").unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);

        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let key = AwsLcVerificationKey::from_rsa_public_key(key.public_key(), false).unwrap();
        let err = key.verify(b"bad-data", b"bad-sig").unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }
}
