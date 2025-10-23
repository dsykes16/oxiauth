//! Traits representing full list of JWT Claims registered in RFC 7519

/// `iss` (Issuer) Claim
///
/// Ref: [RFC 7519 4.1.1](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1>)
pub trait Iss {
    /// Return `iss` (Issuer) claim from JWS
    fn iss(&self) -> &str;
}

/// `sub` (Subject) Claim
///
/// Ref: [RFC 7519 4.1.2](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2>)
pub trait Sub {
    /// Return `sub` (Subject) claim from JWS
    fn sub(&self) -> &str;
}

/// `aud` (Audience) Claim
///
/// Ref: [RFC 7519 4.1.3](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3>)
pub trait Aud {
    /// Return `aud` (Audience) claim from JWS
    fn aud(&self) -> impl Iterator<Item = impl AsRef<str>>;
}

/// `exp` (Expiration Time) Claim
///
/// Ref: [RFC 7519 4.1.4](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4>)
pub trait Exp {
    /// Return `exp` (Expiration Time) claim from JWS
    fn exp(&self) -> i64;
}

/// `nbf` (Not Before) Claim
///
/// Ref: [RFC 7519 4.1.5](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5>)
pub trait Nbf {
    /// Return `nbf` (Not Before) claim from JWS
    fn nbf(&self) -> i64;
}

/// `iat` (Issued At) Claim
///
/// Ref: [RFC 7519 4.1.6](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6>)
pub trait Iat {
    /// Return `iat` (Issued At) claim from JWS
    fn iat(&self) -> i64;
}

/// `jti` (JWT ID) Claim
///
/// Ref: [RFC 7519 4.1.7](<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7>)
pub trait Jti {
    /// Return `jti` (JWT ID) claim from JWS
    fn jti(&self) -> &str;
}
