//! [`openssl`] crypto backend implementation
//!
//! Implements [`Signer`] and [`VerificationKey`] on various
//! [`openssl`] types to permit their direct usage in JWT
//! operations.
//!
//! [`Signer`]: crate::encoding::Signer
//! [`VerificationKey`]: crate::validation::VerificationKey

mod sign;
mod verify;

use openssl::{
    ec::EcKeyRef,
    hash::MessageDigest,
    nid::Nid,
    pkey::{
        HasPublic,
        Id,
        PKey,
        PKeyRef,
        Private,
    },
};

use crate::Algorithm;

/// OpenSSL [`HmacKey`] for signing and/or verifying JWTs
pub struct HmacKey {
    key: PKey<Private>,
    alg: Algorithm,
}
impl HmacKey {
    /// Constructs a new HS256 key
    ///
    /// # Panics
    ///
    /// If secret is an empty slice.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn hs256(secret: &[u8]) -> Self {
        let key = PKey::hmac(secret).expect("hmac secret must not be zero-length");
        let alg = Algorithm::HS256;
        Self { key, alg }
    }

    /// Constructs a new HS384 key
    ///
    /// # Panics
    ///
    /// If secret is an empty slice.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn hs384(secret: &[u8]) -> Self {
        let key = PKey::hmac(secret).expect("hmac secret must not be zero-length");
        let alg = Algorithm::HS384;
        Self { key, alg }
    }

    /// Constructs a new HS512 key
    ///
    /// # Panics
    ///
    /// If secret is an empty slice.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn hs512(secret: &[u8]) -> Self {
        let key = PKey::hmac(secret).expect("hmac secret must not be zero-length");
        let alg = Algorithm::HS512;
        Self { key, alg }
    }

    pub(crate) fn digest(&self) -> MessageDigest {
        match self.alg {
            Algorithm::HS256 => MessageDigest::sha256(),
            Algorithm::HS384 => MessageDigest::sha384(),
            Algorithm::HS512 => MessageDigest::sha512(),
            _ => unreachable!(
                "all hmac algorithms are covered; HmacKey does not support non-Hmac algorithms"
            ),
        }
    }
}

fn map_pkey_alg<T>(key: &PKeyRef<T>) -> Option<Algorithm>
where
    T: HasPublic,
{
    match (key.id(), key.bits()) {
        (Id::RSA, 2048) => Some(Algorithm::RS256),
        (Id::RSA, 3072) => Some(Algorithm::RS384),
        (Id::RSA, 4096) => Some(Algorithm::RS512),
        (Id::RSA_PSS, 2048) => Some(Algorithm::PS256),
        (Id::RSA_PSS, 3072) => Some(Algorithm::PS384),
        (Id::RSA_PSS, 4096) => Some(Algorithm::PS512),
        (Id::EC, _) => {
            let eckey = key.ec_key().ok()?;
            ec_curve_alg(&eckey)
        }
        // TODO: swap for Ed25519 if/when EdDSA header is deprecated
        // Ref: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-13.html#name-deprecated-polymorphic-jose
        (Id::ED25519, 256) => Some(Algorithm::EdDSA),
        (Id::ED448, 456) => Some(Algorithm::Ed448),
        // TODO: add MlDsa algs when rust-openssl supports them (Ref: https://github.com/rust-openssl/rust-openssl/issues/2393)
        _ => None,
    }
}

fn ec_curve_alg<T>(key: &EcKeyRef<T>) -> Option<Algorithm>
where
    T: HasPublic,
{
    match key.group().curve_name()? {
        Nid::X9_62_PRIME256V1 => Some(Algorithm::ES256),
        Nid::SECP256K1 => Some(Algorithm::ES256K),
        Nid::SECP384R1 => Some(Algorithm::ES384),
        Nid::SECP521R1 => Some(Algorithm::ES512),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use openssl::{
        bn::{
            BigNum,
            BigNumContext,
        },
        ec::{
            EcGroup,
            EcKey,
            EcPoint,
        },
        nid::Nid,
        pkey::PKey,
    };

    use super::ec_curve_alg;
    use crate::crypto::openssl::HmacKey;

    #[test]
    #[should_panic(expected = "internal error: entered unreachable code")]
    // this is unreachable by any external crates since HmacKey
    // fields are private.
    fn hmac_key_must_be_hmac() {
        let key = HmacKey {
            alg: crate::Algorithm::PS256,
            key: PKey::hmac(&[b'a'; 32]).unwrap(),
        };
        key.digest();
    }

    #[test]
    fn unsupported_ec_curve_returns_no_alg() {
        let keypair = EcKey::generate(&EcGroup::from_curve_name(Nid::SECT283R1).unwrap()).unwrap();
        let keypair = PKey::from_ec_key(keypair).unwrap();
        let eckey = keypair.ec_key().unwrap();

        assert!(ec_curve_alg(&eckey).is_none());
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn unnamed_ec_curve_rejected() {
        // P-256 params (use any valid params you want)
        let p = BigNum::from_hex_str(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        )
        .unwrap();
        let a = BigNum::from_hex_str(
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        )
        .unwrap();
        let b = BigNum::from_hex_str(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        )
        .unwrap();
        let gx = BigNum::from_hex_str(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )
        .unwrap();
        let gy = BigNum::from_hex_str(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )
        .unwrap();
        let n = BigNum::from_hex_str(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        )
        .unwrap();
        let h = BigNum::from_u32(1).unwrap();

        let mut ctx = BigNumContext::new().unwrap();

        // Create an explicit-parameter group (unnamed)
        let mut group = EcGroup::from_components(p, a, b, &mut ctx).unwrap();
        group.set_asn1_flag(openssl::ec::Asn1Flag::EXPLICIT_CURVE);

        // Set the generator, order, cofactor
        let mut g = EcPoint::new(&group).unwrap();
        g.set_affine_coordinates_gfp(&group, &gx, &gy, &mut ctx)
            .unwrap();
        group.set_generator(g, n, h).unwrap();

        // Generate a key on this unnamed curve
        let key = EcKey::generate(&group).unwrap();
        let _pkey = PKey::from_ec_key(key.clone()).unwrap();

        assert!(key.group().curve_name().is_none());
        assert!(ec_curve_alg(&key).is_none());
    }
}
