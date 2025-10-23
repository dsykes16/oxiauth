use aws_lc_rs::{
    error::Unspecified,
    hmac::{
        Algorithm as HmacAlgorithm,
        Context as HmacContext,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        Key as HmacKey,
    },
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P256K1_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED_SIGNING,
        ECDSA_P521_SHA512_FIXED_SIGNING,
        EcdsaKeyPair,
        Ed25519KeyPair,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        RsaKeyPair,
        RsaSignatureEncoding,
    },
    unstable::signature::{
        ML_DSA_44_SIGNING,
        ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
};

use crate::{
    Algorithm,
    encoding::{
        JwtEncodingError,
        Signer,
    },
};

fn map_rsa_alg(algorithm: Algorithm) -> Option<&'static RsaSignatureEncoding> {
    match algorithm {
        Algorithm::RS256 => Some(&RSA_PKCS1_SHA256),
        Algorithm::PS256 => Some(&RSA_PSS_SHA256),
        Algorithm::RS384 => Some(&RSA_PKCS1_SHA384),
        Algorithm::PS384 => Some(&RSA_PSS_SHA384),
        Algorithm::RS512 => Some(&RSA_PKCS1_SHA512),
        Algorithm::PS512 => Some(&RSA_PSS_SHA512),
        _ => None,
    }
}

impl Signer for PqdsaKeyPair {
    type Error = Unspecified;
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        let jalg = match algorithm {
            Algorithm::MlDsa44 => Ok(&ML_DSA_44_SIGNING),
            Algorithm::MlDsa65 => Ok(&ML_DSA_65_SIGNING),
            Algorithm::MlDsa87 => Ok(&ML_DSA_87_SIGNING),
            _ => Err(JwtEncodingError::UnsupportedAlgorithm),
        }?;
        let kalg = self.algorithm();
        if kalg.eq(jalg) {
            Ok(())
        } else {
            Err(JwtEncodingError::WrongAlgorithm)
        }
    }
    fn siglen(&self) -> usize {
        self.algorithm().signature_len()
    }
    fn sign_jwt(
        &self,
        _: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        // TODO: optimize this to append directly to a mutable slice of the JWT
        let mut sig = vec![0; self.siglen()];
        let slen = self.sign(jwt.as_bytes(), &mut sig)?;
        debug_assert_eq!(slen, self.siglen());
        self.append_sig(&sig, jwt);
        Ok(())
    }
}

impl Signer for RsaKeyPair {
    type Error = Unspecified;
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        match algorithm {
            Algorithm::RS256 | Algorithm::PS256 => {
                if self.public_modulus_len() == 256 {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            Algorithm::RS384 | Algorithm::PS384 => {
                if self.public_modulus_len() == 384 {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            Algorithm::RS512 | Algorithm::PS512 => {
                if self.public_modulus_len() == 512 {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            _ => Err(JwtEncodingError::UnsupportedAlgorithm),
        }
    }

    fn sign_jwt(
        &self,
        algorithm: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        //let algorithm = map_rsa_alg(algorithm, self.public_modulus_len())
        let algorithm = map_rsa_alg(algorithm).ok_or(JwtEncodingError::UnsupportedAlgorithm)?;
        let rng = SystemRandom::new();

        // PERF: the below was benchmarked and found to make negigible difference. RSA signing
        // is already horribly slow (~400µs); the few ns saved by keeping it on the stack isn't
        // worth it here.
        // let mut buf: [u8; 512] = [0; 512];
        // let mut sig = &mut buf[0..self.siglen()];
        let mut sig = vec![0; self.public_modulus_len()];
        self.sign(algorithm, &rng, jwt.as_bytes(), &mut sig)?;
        self.append_sig(sig, jwt);
        Ok(())
    }

    fn siglen(&self) -> usize {
        self.public_modulus_len()
    }
}

impl Signer for EcdsaKeyPair {
    type Error = Unspecified;
    fn siglen(&self) -> usize {
        let kalg = self.algorithm();
        if std::ptr::addr_eq(kalg, &raw const ECDSA_P256_SHA256_FIXED_SIGNING)
            || std::ptr::addr_eq(kalg, &raw const ECDSA_P256K1_SHA256_FIXED_SIGNING)
        {
            64
        } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P384_SHA384_FIXED_SIGNING) {
            96
        } else if std::ptr::addr_eq(kalg, &raw const ECDSA_P521_SHA512_FIXED_SIGNING) {
            132
        } else {
            // SAFETY: the public [`encoding::encode`] function calls [`check_alg`] first, so this
            // should never be reached.
            unreachable!("check_alg should be called before siglen")
        }
    }

    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        let kalg = self.algorithm();
        match algorithm {
            Algorithm::ES256 => {
                if std::ptr::addr_eq(kalg, &raw const ECDSA_P256_SHA256_FIXED_SIGNING) {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            Algorithm::ES256K => {
                if std::ptr::addr_eq(kalg, &raw const ECDSA_P256K1_SHA256_FIXED_SIGNING) {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            Algorithm::ES384 => {
                if std::ptr::addr_eq(kalg, &raw const ECDSA_P384_SHA384_FIXED_SIGNING) {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            Algorithm::ES512 => {
                if std::ptr::addr_eq(kalg, &raw const ECDSA_P521_SHA512_FIXED_SIGNING) {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            }
            _ => Err(JwtEncodingError::UnsupportedAlgorithm),
        }
    }

    fn sign_jwt(
        &self,
        _: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        let sig = self.sign(&SystemRandom::new(), jwt.as_bytes())?;
        self.append_sig(sig, jwt);
        Ok(())
    }
}

impl Signer for Ed25519KeyPair {
    type Error = Unspecified;
    fn siglen(&self) -> usize {
        64
    }

    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        if matches!(algorithm, Algorithm::EdDSA) {
            Ok(())
        } else {
            Err(JwtEncodingError::UnsupportedAlgorithm)
        }
    }

    fn sign_jwt(
        &self,
        _: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        let sig = self.sign(jwt.as_bytes());
        self.append_sig(sig, jwt);
        Ok(())
    }
}

fn map_hmac_alg<S>(algorithm: Algorithm) -> Result<HmacAlgorithm, JwtEncodingError<S::Error>>
where
    S: Signer,
{
    match algorithm {
        Algorithm::HS256 => Ok(HMAC_SHA256),
        Algorithm::HS384 => Ok(HMAC_SHA384),
        Algorithm::HS512 => Ok(HMAC_SHA512),
        _ => Err(JwtEncodingError::UnsupportedAlgorithm),
    }
}

impl Signer for HmacKey {
    type Error = Unspecified;
    fn siglen(&self) -> usize {
        self.algorithm().digest_algorithm().output_len()
    }
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        let expected_key_alg = map_hmac_alg::<Self>(algorithm)?;
        if expected_key_alg == self.algorithm() {
            Ok(())
        } else {
            Err(JwtEncodingError::WrongAlgorithm)
        }
    }
    fn sign_jwt(
        &self,
        _: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        let mut ctx = HmacContext::with_key(self);
        ctx.update(jwt.as_bytes());
        let sig = ctx.sign();
        self.append_sig(sig.as_ref(), jwt);
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use aws_lc_rs::{
        hmac::{
            HMAC_SHA256,
            HMAC_SHA384,
            HMAC_SHA512,
            Key as HmacKey,
        },
        rand::SystemRandom,
        rsa::KeySize,
        signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING,
            ECDSA_P256K1_SHA256_FIXED_SIGNING,
            ECDSA_P384_SHA384_FIXED_SIGNING,
            ECDSA_P521_SHA512_FIXED_SIGNING,
            EcdsaKeyPair,
            Ed25519KeyPair,
            RsaKeyPair,
        },
        unstable::signature::{
            ML_DSA_44_SIGNING,
            ML_DSA_65_SIGNING,
            ML_DSA_87_SIGNING,
            PqdsaKeyPair,
        },
    };

    use crate::{
        Algorithm,
        encoding::{
            JwtEncodingError,
            Signer,
        },
    };

    #[test]
    fn hmac_sha256_check_alg() {
        let key = HmacKey::generate(HMAC_SHA256, &SystemRandom::new()).unwrap();
        key.check_alg(Algorithm::HS256).unwrap();

        // wrong hmac digest
        let err = key.check_alg(Algorithm::HS384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not hmac
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn hmac_sha384_check_alg() {
        let key = HmacKey::generate(HMAC_SHA384, &SystemRandom::new()).unwrap();
        key.check_alg(Algorithm::HS384).unwrap();

        // wrong hmac digest
        let err = key.check_alg(Algorithm::HS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not hmac
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn hmac_sha512_check_alg() {
        let key = HmacKey::generate(HMAC_SHA512, &SystemRandom::new()).unwrap();
        key.check_alg(Algorithm::HS512).unwrap();

        // wrong hmac digest
        let err = key.check_alg(Algorithm::HS384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not hmac
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn ed25519_check_alg() {
        let key = Ed25519KeyPair::generate().unwrap();
        key.check_alg(Algorithm::EdDSA).unwrap();

        // not ed25519
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn es256_check_alg() {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        key.check_alg(Algorithm::ES256).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::ES256K).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES512).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not ecdsa
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn es256k_check_alg() {
        let key = EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).unwrap();
        key.check_alg(Algorithm::ES256K).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES512).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not ecdsa
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn es384_check_alg() {
        let key = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        key.check_alg(Algorithm::ES384).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES512).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not ecdsa
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn es512_check_alg() {
        let key = EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).unwrap();
        key.check_alg(Algorithm::ES512).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::ES384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not ecdsa
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn rs256_check_alg() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::RS384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::RS512).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not rsa
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn rs384_check_alg() {
        let key = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::RS512).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not rsa
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn rs_512_check_alg() {
        let key = RsaKeyPair::generate(KeySize::Rsa4096).unwrap();

        // wrong digest
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::RS384).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // not rsa
        let err = key.check_alg(Algorithm::ES256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn rsa_key_signing_with_wrong_algo_errs() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();

        let mut jwt = "e30.e30".into();
        let err = key.sign_jwt(crate::Algorithm::ES256, &mut jwt).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn mldsa44_check_alg() {
        let key = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap();
        key.check_alg(Algorithm::MlDsa44).unwrap();

        // wrong alg
        let err = key.check_alg(Algorithm::MlDsa65).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::MlDsa87).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // unsupported alg for key family
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn mldsa65_check_alg() {
        let key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        key.check_alg(Algorithm::MlDsa65).unwrap();

        // wrong alg
        let err = key.check_alg(Algorithm::MlDsa44).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::MlDsa87).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // unsupported alg for key family
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }

    #[test]
    fn mldsa87_check_alg() {
        let key = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        key.check_alg(Algorithm::MlDsa87).unwrap();

        // wrong alg
        let err = key.check_alg(Algorithm::MlDsa44).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
        let err = key.check_alg(Algorithm::MlDsa65).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));

        // unsupported alg for key family
        let err = key.check_alg(Algorithm::RS256).unwrap_err();
        assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
    }
}
