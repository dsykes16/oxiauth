use thiserror::Error;

/// Errors raised during JWT Decoding and Validation
#[derive(Debug, Error, PartialEq, Eq)]
pub enum JwtError {
    /// Error raised by [`KeyProvider`] when a [`VerificationKey`] cannot be found
    #[error("verification key not found in keystore")]
    VerificationKeyNotFound,

    /// Error raised by [`VerificationKey`] when the signature is invalid
    #[error("invalid signature")]
    InvalidSignature,

    /// Error raised when a JWT section is not valid base64 url-safe encoded
    #[error("jwt must use base64 url safe encoding")]
    InvalidEncoding,

    /// Error raised when JWT claims cannot be deserialized from JSON into the target type
    #[error("claims could not be deserialized")]
    ClaimsDeserialization,

    /// Error raised when JWT header cannot be deserialized from JSON into the target type
    #[error("header could not be deserialized")]
    HeaderDeserialization,

    /// Error raised when JWT contains an invalid number of dot-delimited sections
    #[error("jwt contained wrong number of dot-delimited sections")]
    InvalidSectionCount(#[from] SplitError),

    /// Error raised when `alg` header field of JWT does not match [`VerificationKey::alg`]
    #[error("jwt 'alg' header field did not match algorithm verification was attempted with")]
    WrongAlgorithm,

    /// Error raised when `aud` field of JWT header does not contain expected value
    #[error("jwt 'aud' header did not contain expected audience")]
    WrongAudience,

    /// Error raised when `iss` (Issuer) field of JWT header does not contain expected value
    #[error("jwt 'iss' header did not contain expected issuer")]
    WrongIssuer,

    /// Error raised when `scope` field of JWT claims does not contain expected value(s)
    #[error("jwt 'scope' claim did not contain an expected scope")]
    WrongScope,

    /// Error raised when `typ` (Type) field of JWT header does not contain expected value
    #[error("jwt 'typ' header was not in set of accepted types")]
    WrongType,

    /// Error raised when `sub` (Subject) field of JWT claims does not contain expected value
    #[error("jwt 'sub' claim was not in set of accepted subscribers")]
    WrongSubscriber,

    /// Error raised when `exp` (Expiration Time) field of JWT indicates JWT is expired
    #[error("jwt 'exp' claim indicates token is expired")]
    Expired,

    /// Error raised when `nbf` (Not Before Time) field of JWT indicates JWT is not yet valid
    #[error("jwt 'nbf' claim indicates token is not yet valid")]
    NotValidYet,

    /// Error raised when `iat` (Issued At) field of JWT indicates JWT is not yet valid
    #[error("jwt 'iat' claim indicates token was issued in the future")]
    IssuedInFuture,

    /// Generic error raised by any arbitrary [`TokenValidator`]
    #[error("custom field validation error")]
    CustomValidationError(&'static str),

    /// Error raised when crypto backend or key type does not support the JWT's algorithm
    #[error("validator does not support this algorithm")]
    UnsupportedAlgorithm,

    /// Error raised when the crypto backend behind a given [`VerificationKey`] encounters an error
    /// during signature validation
    #[error("signature validation was unable to be performed with provided key")]
    KeyError,

    /// Error raised when JWT is larger than the size limit specified for the [`ValidationPipeline`]
    #[error("jwt was above set size threshold")]
    OverSizeThreshold,
}

/// Errors raised during Comapct-encoded JWT split process
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SplitError {
    /// Error raised when Compact-encoded JWS contains less then three sections
    #[error("token contained less than three sections")]
    Undersized,

    /// Error raised when Compact-encoded JWS contains more than three sections
    #[error("token contained more than three sections")]
    Oversized,
}
