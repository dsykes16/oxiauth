//! Provides JWT validation functionality
pub mod keystore;

pub(crate) mod validator;

pub use pipeline::ValidationPipeline;
pub use validator::TokenValidator;

mod pipeline;

#[cfg(feature = "async")]
// WARNING: async support is experimental
mod async_pipeline;

use crate::{
    Algorithm,
    JwtError,
};

/// A [`VerificationKey`] used to validate JWT signatures.
pub trait VerificationKey {
    /// Return the key's [`Algorithm`] or [`None`] if algorithm is undeterminable or unsupported
    fn alg(&self) -> Option<Algorithm>;

    /// Verify a JWT's signature.
    ///
    /// # Parameters
    ///
    /// - `message` is the dot-delimited base-64-url encoded message section of
    ///   the JWT, including the header and payload, but not the signature.
    ///   Ref: <https://datatracker.ietf.org/doc/html/rfc7515#section-7.1>
    /// - `signature` is the decoded signature component of the JWT.
    ///
    /// # Errors
    ///
    ///  This method MUST return an error when the signature is invalid
    ///  or cannot be validated.
    ///
    /// - [`JwtError::InvalidSignature`] when the signature is not valid.
    ///
    /// This method MAY return a [`JwtError::KeyError`] when an issue with
    /// the underlying verification key is encountered.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError>;
}

/// A [`KeyProvider`] which, given an unvalidated JWT's header and claims, can determine
/// the appropriate key to attempt validation with or otherwise return an error.
pub trait KeyProvider<H: ?Sized, C: ?Sized> {
    /// Type of [`VerificationKey`] provided
    type Key: VerificationKey;

    /// Attempt to resolve the key to be used for JWT signature verification.
    ///
    /// # Errors
    ///
    /// - [`JwtError::VerificationKeyNotFound`] when the appropriate key is not available
    ///   to the [`KeyProvider`] (e.g. `kid` field on `header` indicates a key which does
    ///   not exist in the keystore).
    fn resolve_key(&self, header: &H, claims: &C) -> Result<&Self::Key, JwtError>;
}

/// Static provider that unconditionally returns a single [`VerificationKey`]
pub struct StaticKeyProvider<VK: VerificationKey> {
    key: VK,
}

impl<VK: VerificationKey> StaticKeyProvider<VK> {
    /// Instantiate a new [`StaticKeyProvider`] wrapping the given [`VerificationKey`].
    pub const fn new(key: VK) -> Self {
        Self { key }
    }
}

impl<H, C, VK: VerificationKey> KeyProvider<H, C> for StaticKeyProvider<VK> {
    type Key = VK;
    fn resolve_key(&self, _: &H, _: &C) -> Result<&VK, JwtError> {
        Ok(&self.key)
    }
}

impl<VK> From<VK> for StaticKeyProvider<VK>
where
    VK: VerificationKey,
{
    fn from(value: VK) -> Self {
        Self { key: value }
    }
}
