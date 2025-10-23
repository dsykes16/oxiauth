use base64_simd::URL_SAFE_NO_PAD as b64;
use serde::Serialize;
use thiserror::Error;

use crate::{
    Algorithm,
    header::Alg,
};

/// JWT `Signer`, usually implemeted on a cryptographic key representation or a wrapper
/// around a cryptographic key.
pub trait Signer {
    /// Crypto backend error type to be wrapped by [`JwtEncodingError::SigningError`]
    type Error: Sized + std::error::Error;

    /// This method is called prior to attempting signing to confirm the `Signer` supports
    /// the `algorithm` specified by the JWT header.
    ///
    /// # Errors
    ///
    /// This method MUST return:
    /// - [`JwtEncodingError::WrongAlgorithm`] when the `algorithm` does not match
    ///   the `Signer` algorithm(s).
    /// - [`JwtEncodingError::UnsupportedAlgorithm`] if the `algorithm` is not supported
    ///   by the crypto backend or key family.
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>>;

    /// This method is provided with the base-64 encoded, dot-delimited JWT header and
    /// claims. It MUST calculate a signature with the key's algorithm and append it
    /// as the final dot-delimited section of the JWT. It MAY make use of the
    /// [`Signer::append_sig`] default implementation to concatenate the signature.
    ///
    /// # Errors
    ///
    /// - [`JwtEncodingError::SigningError`] when the JWT cannot be successfully signed
    /// - [`JwtEncodingError::WrongAlgorithm`] when the `algorithm` arg (from JWT header)
    ///   does not match the `Signer` algorithm. This error will not be reached in normal
    ///   usage as [`Signer::check_alg`] is called prior to attempting signing.
    /// - [`JwtEncodingError::UnsupportedAlgorithm`] when the `algorithm` is unsupported by
    ///   the crypto backend or key type. This error will not be reached in normal usage
    ///   because the [`Signer::check_alg`] method is called prior to attempting signing.
    ///
    /// The following [`JwtEncodingError`] types SHOULD NOT be returned:
    /// - [`JwtEncodingError::HeaderSerialization`] because JWT headers have already been
    ///   serialized at this point in the encoding process
    /// - [`JwtEncodingError::ClaimsSerialization`] because JWT claims have already been
    ///   serialized at this point in the encoding process
    fn sign_jwt(
        &self,
        algorithm: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>>;

    /// This method MUST return the exact size, in bytes, of the signature produced by
    /// the `Signer`
    fn siglen(&self) -> usize;

    /// Convenience method to base64-encode and append `sig` as the final dot-delimited
    /// section of the `jwt` to be called from [`Signer::sign_jwt`].
    /// Implementors should not need to override this, but may choose to perform their
    /// own in-place operations as an alternative to calling this method.
    fn append_sig(&self, sig: impl AsRef<[u8]>, jwt: &mut String) {
        jwt.push('.');
        b64.encode_append(sig, jwt);
    }
}

/// Errors that may be returned during the JWT Encoding/Signing process
#[derive(Debug, Error)]
pub enum JwtEncodingError<T>
where
    T: Sized + std::error::Error,
{
    /// Error raised when JWT header cannot be serialized
    #[error("header could not be serialized")]
    HeaderSerialization(serde_json::Error),

    /// Error raised when JWT claims cannot be serialized
    #[error("claims could not be serialized")]
    ClaimsSerialization(serde_json::Error),

    /// Error raised when `alg` field of JWT header does not match `Signer::alg`
    #[error("header 'alg' field did not match signing key algorithm")]
    WrongAlgorithm,

    /// Error raised when `alg` field of JWT header is unsupported by crypto backend
    /// or `Signer` key family (e.g. attempting EdDSA sig w/ RSA keypair).
    #[error("signing key algorithm is not supported by crypto backend")]
    UnsupportedAlgorithm,

    /// Generic signing error to wrap crypto backend error or other custom error set specific
    /// to `Signer` implementation.
    #[error("signing error")]
    SigningError(#[from] T),
}

/// Signs and Encodes a JWT with the given `key`, `header`, and `claims`
///
/// # Errors
///
/// - [`JwtEncodingError::HeaderSerialization`] when header cannot be serialized
///   to JSON
/// - [`JwtEncodingError::ClaimsSerialization`] when claims cannot be serialized
///   to JSON
/// - Any [`JwtEncodingError`] raised by the `sign_jwt` method of the `key`, typically
///   [`JwtEncodingError::WrongAlgorithm`] if the `header` algorithm does not match
///   the key algorithm.
pub fn encode<H, C, S>(
    key: &S,
    header: &H,
    claims: &C,
) -> Result<String, JwtEncodingError<S::Error>>
where
    S: Signer,
    S::Error: Sized + std::error::Error,
    H: Serialize + Alg,
    C: Serialize,
{
    key.check_alg(header.alg())?;

    let serialized_header =
        serde_json::to_vec(&header).map_err(JwtEncodingError::HeaderSerialization)?;
    let serialized_claims =
        serde_json::to_vec(&claims).map_err(JwtEncodingError::ClaimsSerialization)?;

    let mut jwt: String = String::with_capacity(
        b64.encoded_length(serialized_header.len())
            + 1
            + b64.encoded_length(serialized_claims.len())
            + 1
            + b64.encoded_length(key.siglen()),
    );

    #[cfg(debug_assertions)]
    let initial_cap = jwt.capacity();

    b64.encode_append(serialized_header, &mut jwt);
    jwt.push('.');
    b64.encode_append(serialized_claims, &mut jwt);
    key.sign_jwt(header.alg(), &mut jwt)?;

    #[cfg(debug_assertions)]
    debug_assert_eq!(initial_cap, jwt.capacity());

    Ok(jwt)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use thiserror::Error;

    use super::{
        Alg,
        Algorithm,
        JwtEncodingError,
        Signer,
        encode,
    };

    #[derive(Debug)]
    struct MockKey;
    impl MockKey {
        fn new() -> Self {
            Self {}
        }
    }
    #[derive(Debug, Error)]
    enum MockSignerError {
        #[error("fake error")]
        FakeError,
    }
    impl Signer for MockKey {
        type Error = MockSignerError;
        fn siglen(&self) -> usize {
            8
        }
        fn sign_jwt(
            &self,
            _: Algorithm,
            jwt: &mut String,
        ) -> Result<(), JwtEncodingError<Self::Error>> {
            self.append_sig(b"ID10T", jwt);
            Ok(())
        }
        fn check_alg(&self, header_alg: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
            if matches!(header_alg, Algorithm::RS256) {
                Ok(())
            } else {
                Err(JwtEncodingError::WrongAlgorithm)
            }
        }
    }

    #[derive(Debug, Default, serde::Serialize)]
    struct H {
        alg: Algorithm,
    }
    impl Alg for H {
        fn alg(&self) -> Algorithm {
            self.alg
        }
    }

    #[derive(Debug, serde::Serialize)]
    struct C {
        claim: String,
    }
    impl Default for C {
        fn default() -> Self {
            Self {
                claim: "test".into(),
            }
        }
    }

    #[test]
    fn append_sig() {
        let mut jwt = "e30.e30".into();

        MockKey::new()
            .sign_jwt(Algorithm::default(), &mut jwt)
            .unwrap();

        assert_eq!(jwt, "e30.e30.SUQxMFQ");
    }

    #[test]
    fn encode_ok() {
        // {"alg":"RS256"}
        let expected_header = "eyJhbGciOiJSUzI1NiJ9";
        // {"claim":"test"}
        let expected_claims = "eyJjbGFpbSI6InRlc3QifQ";
        let jwt = encode(&MockKey::new(), &H::default(), &C::default()).unwrap();
        assert_eq!(jwt, format!("{expected_header}.{expected_claims}.SUQxMFQ"));
    }

    #[test]
    fn encode_bad_header() {
        struct BadHeader;
        impl Alg for BadHeader {
            fn alg(&self) -> Algorithm {
                Algorithm::default()
            }
        }
        impl serde::Serialize for BadHeader {
            fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("fake error"))
            }
        }

        let err = encode(&MockKey::new(), &BadHeader {}, &C::default()).unwrap_err();
        assert!(matches!(err, JwtEncodingError::HeaderSerialization(_)));
    }

    #[test]
    fn encode_bad_claims() {
        struct BadClaims;
        impl Alg for BadClaims {
            fn alg(&self) -> Algorithm {
                Algorithm::default()
            }
        }
        impl serde::Serialize for BadClaims {
            fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("fake error"))
            }
        }

        let err = encode(&MockKey::new(), &H::default(), &BadClaims {}).unwrap_err();
        assert!(matches!(err, JwtEncodingError::ClaimsSerialization(_)));
    }

    #[test]
    fn encode_bad_signer() {
        struct BadKey;
        impl Signer for BadKey {
            type Error = MockSignerError;
            fn check_alg(&self, _: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
                Ok(())
            }
            fn siglen(&self) -> usize {
                0
            }
            fn sign_jwt(
                &self,
                _: Algorithm,
                _: &mut String,
            ) -> Result<(), JwtEncodingError<Self::Error>> {
                Err(JwtEncodingError::SigningError(MockSignerError::FakeError))
            }
        }

        let err = encode(&BadKey {}, &H::default(), &C::default()).unwrap_err();
        assert!(matches!(
            err,
            JwtEncodingError::SigningError(MockSignerError::FakeError)
        ));
    }

    #[test]
    fn encode_wrong_alg() {
        let header = H {
            alg: Algorithm::PS512,
        };
        let err = encode(&MockKey::new(), &header, &C::default()).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn key_provides_wrong_siglen() {
        struct WrongSiglenKey;
        impl Signer for WrongSiglenKey {
            type Error = MockSignerError;
            fn check_alg(&self, _: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
                Ok(())
            }
            fn sign_jwt(
                &self,
                _: Algorithm,
                jwt: &mut String,
            ) -> Result<(), JwtEncodingError<Self::Error>> {
                self.append_sig(b"nonzero", jwt);
                Ok(())
            }
            fn siglen(&self) -> usize {
                0
            }
        }

        encode(&WrongSiglenKey {}, &H::default(), &C::default()).unwrap();
    }
}
