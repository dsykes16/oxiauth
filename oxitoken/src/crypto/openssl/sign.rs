use openssl::{
    ec::EcKeyRef,
    ecdsa::EcdsaSig,
    error::ErrorStack,
    hash::{
        Hasher,
        MessageDigest,
    },
    pkey::{
        HasPrivate,
        PKey,
        PKeyRef,
    },
    rsa::Padding,
    sign::{
        RsaPssSaltlen,
        Signer,
    },
};

use crate::{
    Algorithm,
    crypto::openssl::{
        HmacKey,
        map_pkey_alg,
    },
    encoding::{
        JwtEncodingError,
        Signer as JwtSigner,
    },
};

impl JwtSigner for HmacKey {
    type Error = ErrorStack;
    fn siglen(&self) -> usize {
        self.digest().size()
    }
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        if algorithm == self.alg {
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
        let mut signer = Signer::new(self.digest(), &self.key)?;
        signer.update(jwt.as_bytes())?;
        let sig = signer.sign_to_vec()?;
        self.append_sig(sig, jwt);
        Ok(())
    }
}

impl<T> JwtSigner for PKey<T>
where
    T: HasPrivate,
{
    type Error = ErrorStack;
    fn siglen(&self) -> usize {
        let Some(alg) = map_pkey_alg(self) else {
            unreachable!("check_alg should catch unsupported algs before siglen is ran")
        };
        match alg {
            Algorithm::RS256 | Algorithm::PS256 | Algorithm::HS256 => 256,
            Algorithm::RS384 | Algorithm::PS384 | Algorithm::HS384 => 384,
            Algorithm::RS512 | Algorithm::PS512 | Algorithm::HS512 => 512,
            Algorithm::ES256 | Algorithm::ES256K | Algorithm::EdDSA => 64,
            Algorithm::ES384 => 96,
            Algorithm::ES512 => 132,
            Algorithm::Ed448 => 114,
            _ => unreachable!("check_alg should catch unsupported algs before siglen is ran"),
        }
    }
    fn check_alg(&self, header_alg: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        map_pkey_alg(self).map_or_else(
            || Err(JwtEncodingError::UnsupportedAlgorithm),
            |key_alg| {
                if key_alg == header_alg {
                    Ok(())
                } else {
                    Err(JwtEncodingError::WrongAlgorithm)
                }
            },
        )
    }
    fn sign_jwt(
        &self,
        algorithm: crate::Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        let sig = match algorithm {
            Algorithm::RS256 => rsa_sign(MessageDigest::sha256(), self, jwt.as_bytes(), false),
            Algorithm::RS384 => rsa_sign(MessageDigest::sha384(), self, jwt.as_bytes(), false),
            Algorithm::RS512 => rsa_sign(MessageDigest::sha512(), self, jwt.as_bytes(), false),
            Algorithm::PS256 => rsa_sign(MessageDigest::sha256(), self, jwt.as_bytes(), true),
            Algorithm::PS384 => rsa_sign(MessageDigest::sha384(), self, jwt.as_bytes(), true),
            Algorithm::PS512 => rsa_sign(MessageDigest::sha512(), self, jwt.as_bytes(), true),
            Algorithm::ES256 | Algorithm::ES256K => ec_sign(
                MessageDigest::sha256(),
                self.ec_key()?.as_ref(),
                jwt.as_bytes(),
            ),
            Algorithm::ES384 => ec_sign(
                MessageDigest::sha384(),
                self.ec_key()?.as_ref(),
                jwt.as_bytes(),
            ),
            Algorithm::ES512 => ec_sign(
                MessageDigest::sha512(),
                self.ec_key()?.as_ref(),
                jwt.as_bytes(),
            ),
            Algorithm::EdDSA | Algorithm::Ed448 => ed_sign(self, jwt.as_bytes()),
            // [`HmacKey`] must be used for HS-family algorithms. The [`HasPublic`] trait on
            // Hmac-family PKeys is a lie, to "verify" an HMAC signature requires [`HasPrivate`].
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 |
            // TODO: ML_DSA is not currently exposed in rust-openssl; implement when available
            // Ref: https://github.com/rust-openssl/rust-openssl/issues/2393
            Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
                Err(JwtEncodingError::UnsupportedAlgorithm)
            }
        }?;
        self.append_sig(sig, jwt);
        Ok(())
    }
}

fn ed_sign<T>(key: &PKeyRef<T>, message: &[u8]) -> Result<Vec<u8>, JwtEncodingError<ErrorStack>>
where
    T: HasPrivate,
{
    let mut signer = Signer::new_without_digest(key)?;
    let signature = signer.sign_oneshot_to_vec(message)?;
    Ok(signature)
}

fn ec_sign<T>(
    digest: MessageDigest,
    key: &EcKeyRef<T>,
    message: &[u8],
) -> Result<Vec<u8>, JwtEncodingError<ErrorStack>>
where
    T: HasPrivate,
{
    let mut digest = Hasher::new(digest)?;
    digest.update(message)?;
    let digest = digest.finish()?;

    let rsig = EcdsaSig::sign(&digest, key)?;
    let plen = key.group().order_bits().div_ceil(8).cast_signed();
    let mut signature = rsig.r().to_vec_padded(plen)?;
    signature.append(&mut rsig.s().to_vec_padded(plen)?);
    Ok(signature)
}

fn rsa_sign<T>(
    digest: MessageDigest,
    key: &PKeyRef<T>,
    message: &[u8],
    pss: bool,
) -> Result<Vec<u8>, JwtEncodingError<ErrorStack>>
where
    T: HasPrivate,
{
    let mut signer = Signer::new(digest, key)?;
    if pss {
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
    }
    signer.update(message)?;
    let sig = signer.sign_to_vec()?;
    Ok(sig)
}
