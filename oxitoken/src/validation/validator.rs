// JUSTIFICATION: using `pub(crate)` makes it immediately obvious that an item
// is not exposed via the public API.
#![allow(clippy::redundant_pub_crate)]
use std::{
    borrow::Borrow,
    collections::HashSet,
    hash::Hash,
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

use crate::{
    JwtError,
    claims::{
        Aud,
        Exp,
        Iat,
        Iss,
        Nbf,
        Sub,
    },
    header::Typ,
};

/// Trait for implementing custom token validator layers
///
/// # Example Implementation
///
/// ```rust
/// use std::collections::HashSet;
/// use oxitoken::{
///#    Algorithm,
///#    header::Alg,
///#    claims::Exp,
///     claims::Iss,
///     error::JwtError,
///     validation::{
///         TokenValidator,
///         ValidationPipeline,
///#        VerificationKey,
///#        StaticKeyProvider,
///     },
/// };
///
/// pub struct IssuerValidator {
///     accepted_issuers: HashSet<String>,
/// }
/// impl IssuerValidator {
///     pub(crate) fn new(accepted_issuers: impl IntoIterator<Item = impl Into<String>>) -> Self {
///         let accepted_issuers = accepted_issuers.into_iter().map(|iss| iss.into());
///         Self {
///             accepted_issuers: HashSet::from_iter(accepted_issuers),
///         }
///     }
/// }
/// impl<H, C> TokenValidator<H, C> for IssuerValidator
/// where
///     C: Iss,
/// {
///     fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
///         if self.accepted_issuers.contains(claims.iss()) {
///             Ok(())
///         } else {
///             Err(JwtError::WrongIssuer)
///         }
///     }
/// }
///
///# #[derive(serde::Deserialize)]
///# struct Header {}
///# impl Alg for Header {
///#     fn alg(&self) -> Algorithm {
///#         Algorithm::HS256
///#     }
///# }
///# #[derive(serde::Deserialize)]
///# struct Claims;
///# impl Iss for Claims {fn iss(&self) -> &str {"fake-iss"}}
///# impl Exp for Claims {fn exp(&self) -> i64 {0}}
///# struct MockVerificationKey;
///# impl VerificationKey for MockVerificationKey {
///#     fn alg(&self) -> Option<Algorithm> { None }
///#     fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<(), crate::JwtError> {
///#         Ok(())
///#     }
///# }
///# fn some_key_provider() -> StaticKeyProvider<MockVerificationKey> {
///#     MockVerificationKey.into()
///# }
///
///fn main() {
///     let key = some_key_provider();
///     let validator =
///         ValidationPipeline::<Header, Claims, _>::builder(key)
///             .with_expiration_validator()
///             .with(IssuerValidator::new([
///                 "oxitoken.example.org",
///                 "jwt.example.org",
///             ]))
///             // additional `.with(...)` calls can be chained here
///             // all validators are ran in-order
///             .build();
///}
/// ```
pub trait TokenValidator<H: ?Sized, C: ?Sized> {
    /// Given the `header` and `claims` for a JWT, perform some validation step.
    ///
    /// # Errors
    ///
    /// This method MUST return a [`JwtError`] if the JWT `header` and/or `claims`
    /// do not pass the validation step performed by this [`TokenValidator`]
    /// implementation. (e.g. [`JwtError::Expired`] if `exp` field is in the past).
    ///
    /// # Returns
    ///
    /// [`Ok`] if, and only if, the validation step performed by this [`TokenValidator`]
    /// succeeds and indicates the JWT is valid.
    fn validate(&self, header: &H, claims: &C) -> Result<(), JwtError>;
}

pub(crate) struct TypeValidator<T>
where
    T: Hash + Eq,
{
    accepted_types: HashSet<T>,
}
impl<T> TypeValidator<T>
where
    T: Hash + Eq,
{
    pub(crate) fn new(accepted_types: impl IntoIterator<Item = T>) -> Self {
        Self {
            accepted_types: HashSet::from_iter(accepted_types),
        }
    }
}
impl<H, C, T> TokenValidator<H, C> for TypeValidator<T>
where
    H: Typ,
    H::Type: Hash + Eq,
    T: Hash + Eq + Borrow<H::Type>,
{
    fn validate(&self, header: &H, _: &C) -> Result<(), JwtError> {
        if self.accepted_types.contains(header.typ()) {
            Ok(())
        } else {
            Err(JwtError::WrongType)
        }
    }
}

pub(crate) struct IssuerValidator {
    expected_issuer: String,
}
impl IssuerValidator {
    pub(crate) const fn new(iss: String) -> Self {
        Self {
            expected_issuer: iss,
        }
    }
}
impl<H, C> TokenValidator<H, C> for IssuerValidator
where
    C: Iss,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if self.expected_issuer == claims.iss() {
            Ok(())
        } else {
            Err(JwtError::WrongIssuer)
        }
    }
}

pub(crate) struct AudienceValidator {
    expected_audience: String,
}
impl AudienceValidator {
    pub(crate) const fn new(aud: String) -> Self {
        Self {
            expected_audience: aud,
        }
    }
}
impl<H, C> TokenValidator<H, C> for AudienceValidator
where
    C: Aud,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if claims.aud().any(|e| e.as_ref() == self.expected_audience) {
            Ok(())
        } else {
            Err(JwtError::WrongAudience)
        }
    }
}

pub(crate) struct NotBeforeValidator;
impl NotBeforeValidator {
    pub(crate) const fn new() -> Self {
        Self {}
    }
}
impl<H, C> TokenValidator<H, C> for NotBeforeValidator
where
    C: Nbf,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if claims.nbf() < now() {
            Ok(())
        } else {
            Err(JwtError::NotValidYet)
        }
    }
}

pub(crate) struct IssuedAtValidator;
impl IssuedAtValidator {
    pub(crate) const fn new() -> Self {
        Self {}
    }
}
impl<H, C> TokenValidator<H, C> for IssuedAtValidator
where
    C: Iat,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if claims.iat() < now() {
            Ok(())
        } else {
            Err(JwtError::IssuedInFuture)
        }
    }
}

pub(crate) struct ExpirationValidator;
impl ExpirationValidator {
    pub(crate) const fn new() -> Self {
        Self {}
    }
}
impl<H, C> TokenValidator<H, C> for ExpirationValidator
where
    C: Exp,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if claims.exp() > now() {
            Ok(())
        } else {
            Err(JwtError::Expired)
        }
    }
}

pub(crate) struct SubscriberValidator {
    accepted_subscribers: HashSet<String>,
}
impl SubscriberValidator {
    pub(crate) fn new(accepted_subscribers: impl Iterator<Item = impl Into<String>>) -> Self {
        let accepted_subscribers = accepted_subscribers.map(Into::into).collect();
        Self {
            accepted_subscribers,
        }
    }
}
impl<H, C> TokenValidator<H, C> for SubscriberValidator
where
    C: Sub,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if self.accepted_subscribers.contains(claims.sub()) {
            Ok(())
        } else {
            Err(JwtError::WrongSubscriber)
        }
    }
}

fn now() -> i64 {
    // SAFETY: system time should never be before the unix epoch, and at second-precision,
    // we've got a couple hundred billion years to go before we wraparound an i64
    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("'tis sadly no longer the summer of '69")
        .as_secs()
        .cast_signed()
}
