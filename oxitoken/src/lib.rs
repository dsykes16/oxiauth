#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![doc = include_str!("../README.md")]

/// Traits supporting implementation of custom JWT header structs
/// and reference-implementations of common JWT standards.
pub mod claims;

/// Error enums
pub mod error;

/// Traits supporting implementation of custom JWT header structs
/// and reference-implementations of common JWT standards.
pub mod header;

/// Functions and traits supporting JWT validation.
pub mod validation;

/// Functionality for encoding JWTs (including signing).
pub mod encoding;

/// Crypto backend implementations (e.g. `aws_lc`, `openssl`)
pub mod crypto;

// WARNING: The decoding module is not considered part of the public API
// and is subject to breaking changes outside SemVer restrictions. It is
// marked `pub` purely for benchmarking purposes.
#[doc(hidden)]
pub mod decoding;

pub use algorithm::Algorithm;

mod algorithm;
use error::JwtError;

/// Provides dangerous (i.e. non-signature-verifying) JWT decoding functionality.
pub mod dangerous {
    use crate::{
        JwtError,
        decoding::{
            DecodedJwtMessage,
            SplitJwt,
        },
    };
    /// Decodes JWT without any signature validation/verification
    ///
    /// DANGER: does NOT validate/verify JWT signature
    ///
    /// If you need to use headers/claims to pick custom keys, then
    /// implement a custom [`KeyProvider`].
    ///
    /// If you need to run custom validation steps, then implement
    /// a [`TokenValidator`].
    ///
    /// [`oxitoken`] was built with those features specifically to
    /// avoid the necessitity of decoding/parsing a JWT more then once,
    /// so this feature should rarely be necessary.
    ///
    /// [`oxitoken`]: crate
    /// [`KeyProvider`]: crate::validation::KeyProvider
    /// [`TokenValidator`]: crate::validation::TokenValidator
    ///
    /// # Errors
    ///
    /// - [`JwtError::InvalidSectionCount`] when the JWT does not contain the requisite
    ///   three sections (note: the signature may be empty)
    /// - [`JwtError::InvalidEncoding`] when the JWT sections are not valid base64
    ///   url-safe encoded
    /// - [`JwtError::HeaderDeserialization`] when the header section cannot be decoded
    ///   by [`serde`] into the specified header struct
    /// - [`JwtError::ClaimsDeserialization`] when the claims section cannot be decoded
    ///   by [`serde`] into the specified claims struct
    pub fn decode<H, C>(jwt: &[u8]) -> Result<(H, C), JwtError>
    where
        H: for<'de> serde::Deserialize<'de>,
        C: for<'de> serde::Deserialize<'de>,
    {
        let parts = SplitJwt::try_from(jwt)?;
        let decoded = DecodedJwtMessage::try_from(&parts)?;
        Ok((
            serde_json::from_slice(decoded.decoded_header())
                .map_err(|_| JwtError::HeaderDeserialization)?,
            serde_json::from_slice(decoded.decoded_claims())
                .map_err(|_| JwtError::ClaimsDeserialization)?,
        ))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use thiserror::Error;

    use crate::{
        Algorithm,
        dangerous::decode,
        encoding::{
            JwtEncodingError,
            Signer,
            encode,
        },
        error::{
            JwtError,
            SplitError,
        },
        header::Alg,
        validation::{
            StaticKeyProvider,
            ValidationPipeline,
            VerificationKey,
        },
    };

    #[derive(Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Header {
        alg: Algorithm,
    }
    impl Alg for Header {
        fn alg(&self) -> Algorithm {
            self.alg
        }
    }

    #[derive(Debug, Hash, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    struct MockKey {}
    impl MockKey {
        fn new() -> Self {
            Self {}
        }
    }
    impl VerificationKey for MockKey {
        fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> {
            Ok(())
        }
        fn alg(&self) -> Option<Algorithm> {
            Some(Algorithm::HS256)
        }
    }

    #[test]
    fn invalid_header_base64() {
        let jwt = b"=.=.=";
        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);
    }

    #[test]
    fn invalid_claims_base64() {
        let jwt = b"e30.=.=";
        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);
    }

    #[test]
    fn invalid_header_json() {
        // header: {}
        // claims: {}
        let jwt = b"e30.e30.";
        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::HeaderDeserialization);

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::HeaderDeserialization);
    }

    #[test]
    fn invalid_claims_json() {
        // header: {"alg":"HS256","typ":"JWT"}
        // claims: {}
        let jwt = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.";

        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::ClaimsDeserialization);

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::ClaimsDeserialization);
    }

    #[test]
    fn invalid_jwt_format_oversized() {
        let jwt = b"...";

        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::InvalidSectionCount(SplitError::Oversized));

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::InvalidSectionCount(SplitError::Oversized));
    }

    #[test]
    fn invalid_jwt_format_undersized() {
        let jwt = b".";

        let err = decode::<Header, Claims>(jwt).unwrap_err();
        assert_eq!(err, JwtError::InvalidSectionCount(SplitError::Undersized));

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::InvalidSectionCount(SplitError::Undersized));
    }

    #[test]
    fn wrong_alg_rejected() {
        // header: {"alg":"HS512"}
        // claims: {"sub":"test"}
        let jwt = b"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0In0.";

        // dangerous::decode should work here; no validation beyond base64 encoding and json deserialization
        decode::<Header, Claims>(jwt).unwrap();

        let err = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(
            MockKey::new().into(),
        )
        .build()
        .verify(jwt)
        .unwrap_err();
        assert_eq!(err, JwtError::WrongAlgorithm);
    }

    #[test]
    fn signature_error_propogation() {
        struct MockKey;
        impl VerificationKey for MockKey {
            fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> {
                Err(JwtError::InvalidSignature)
            }
            fn alg(&self) -> Option<Algorithm> {
                Some(Algorithm::HS512)
            }
        }

        // header: {"alg":"HS512"}
        // claims: {"sub":"test"}
        let jwt = b"eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0In0.";

        let err =
            ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(MockKey {}.into())
                .build()
                .verify(jwt)
                .unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
    }

    #[test]
    fn encode_header_alg_must_match_key_alg() {
        #[derive(Debug, serde::Serialize)]
        struct H;
        impl Alg for H {
            fn alg(&self) -> Algorithm {
                Algorithm::HS256
            }
        }
        #[derive(Debug, serde::Serialize)]
        struct C;
        #[derive(Debug, Error)]
        enum E {}
        struct K;
        impl Signer for K {
            type Error = E;
            fn append_sig(&self, _: impl AsRef<[u8]>, _: &mut String) {
                unimplemented!();
            }
            fn check_alg(
                &self,
                _: Algorithm,
            ) -> Result<(), crate::encoding::JwtEncodingError<Self::Error>> {
                Err(JwtEncodingError::WrongAlgorithm)
            }
            fn sign_jwt(
                &self,
                _: Algorithm,
                _: &mut String,
            ) -> Result<(), JwtEncodingError<Self::Error>> {
                unimplemented!()
            }
            fn siglen(&self) -> usize {
                0
            }
        }

        let key = K {};
        let err = encode(&key, &H {}, &C {}).unwrap_err();
        assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
    }
}
