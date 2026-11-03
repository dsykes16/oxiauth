//! JWT Header Accessor Traits based on RFC 7515 Defined Header Fields

use crate::Algorithm;

/// `alg` (Algorithm) Header Parameter
///
/// Ref: [RFC 7515 4.1.1](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1>)
pub trait Alg {
    /// Return `alg` (Algorithm) header parameter from JWS
    fn alg(&self) -> Algorithm;
}

/// `jku` (JWK Set URL) Header Parameter
///
/// Ref: [RFC 7515 4.1.2](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2>)
///
/// WARNING: only use this if you understand the inherent risks and mitigations, like
/// matching any JWT-provided URL against an allowlist of trusted locations. Fetching
/// keys from an arbitrary `jku` URL lets the token supply its own verification key and
/// can result in server-side request forgery (SSRF).
/// See [RFC 8725 3.10](<https://datatracker.ietf.org/doc/html/rfc8725#section-3.10>).
pub trait Jku {
    /// Return `jku` (JWK Set URL) header parameter from JWS
    fn jku(&self) -> &str;
}

/// `jwk` (JSON Web Key) Header Parameter
///
/// Ref: [RFC 7515 4.1.3](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3>)
///
/// WARNING: only use this if you understand the inherent risks and mitigations, like
/// validating any JWT-provided JWKs against a trusted root.
pub trait Jwk<T> {
    /// Return `jwk` (JSON Web Key) header parameter from JWS
    fn jwk(&self) -> T;
}

/// `kid` (Key ID) Header Parameter
///
/// Ref: [RFC 7515 4.1.4](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4>)
pub trait Kid {
    /// Return `kid` (Key ID) header parameter from JWS
    fn kid(&self) -> &str;
}

/// `x5u` (X.509 URL) Header Parameter
///
/// Ref: [RFC 7515 4.1.5](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5>)
///
/// WARNING: only use this if you understand the inherent risks and mitigations
pub trait X5U {
    /// Type of X.509 URL header parameter (i.e. `x5u` field)
    type X509Url: ?Sized;

    /// Return `x5u` (X.509 URL) header parameter from JWS
    fn x5u(&self) -> &Self::X509Url;
}

/// `x5c` (X.509 Certificate Chain) Header Parameter
///
/// Ref: [RFC 7515 4.1.6](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6>)
///
/// WARNING: only use this if you understand the inherent risks and mitigations
pub trait X5C {
    /// Type of X.509 Certificate Chain header parameter (i.e. `x5c` field)
    type X509CertificateChain: ?Sized;

    /// Return `x5c` (X.509 Certificate Chain) header parameter from JWS
    fn x5c(&self) -> &Self::X509CertificateChain;
}

/// `x5t` (X.509 Certificate SHA-1 Thumbprint) Header Parameter
///
/// Ref: [RFC 7515 4.1.7](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7>)
pub trait X5T {
    /// Type of X.509 Certificate SHA-1 Thumbprint header parameter (i.e. `x5t` field)
    type X509Sha1Thumbprint: ?Sized;

    /// Return `x5t` (X.509 Certificate SHA-1 Thumbprint) header parameter from JWS
    fn x5t(&self) -> &Self::X509Sha1Thumbprint;
}

/// `x5t#S256` (X.509 Certificate SHA-256 Thumbprint) Header Parameter
///
/// Ref: [RFC 7515 4.1.8](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8>)
pub trait X5TS256 {
    /// Type of X.509 Certificate SHA-256 Thumbprint header parameter (i.e. `x5t#S256` field)
    type X509Sha256Thumbprint: ?Sized;

    /// Return `x5t#S256` (X.509 Certificate SHA-256 Thumbprint) header parameter from JWS
    fn x5t_s256(&self) -> &Self::X509Sha256Thumbprint;
}

/// `typ` (Type) Header Parameter
///
/// Ref: [RFC 7515 4.1.9](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9>)
pub trait Typ {
    /// Type of JWT Type header parameter (i.e. `typ` field)
    type Type: ?Sized;
    /// Return `typ` (Type) header parameter from JWS
    fn typ(&self) -> &Self::Type;
}

/// `cty` (Content Type) Header Parameter
///
/// Ref: [RFC 7515 4.1.10](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10>)
pub trait Cty {
    /// Type of JWT Content Type header parameter (i.e. `cty` field)
    type ContentType: ?Sized;
    /// Return `cty` (Content Type) header parameter from JWS
    fn cty(&self) -> &Self::ContentType;
}

/// `crit` (Critical) Header Parameter
///
/// Ref: [RFC 7515 4.1.11](<https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11>)
///
/// A JWS MUST be rejected if `crit` lists any header parameter the recipient does not
/// understand and process. [`oxitoken`](crate) does not enforce this: [`serde`] ignores
/// unknown fields by default, so a header struct without a `crit` field will silently
/// accept tokens that use it. To enforce it, implement [`Crit`] and add a
/// [`TokenValidator`](crate::validation::TokenValidator) that rejects unsupported
/// entries, or use `#[serde(deny_unknown_fields)]` to reject any header field the
/// struct does not define.
pub trait Crit {
    /// Type of JWT Critical header parameter (i.e. `crit` field)
    type Critical: ?Sized;
    /// Return `crit` (Critical) header parameter from JWS
    fn crit(&self) -> &Self::Critical;
}
