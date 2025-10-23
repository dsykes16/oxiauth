use std::fmt::Display;

/// JWS Signature Algorithm
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Algorithm {
    /// `HMAC` using `SHA-256`
    HS256,

    /// `HMAC` using `SHA-384`
    HS384,

    /// `HMAC` using `SHA-512`
    HS512,

    /// `RSASSA-PKCS1-v1_5` using `SHA-256`
    #[default]
    RS256,

    /// `RSASSA-PKCS1-v1_5` using `SHA-384`
    RS384,

    /// `RSASSA-PKCS1-v1_5` using `SHA-512`
    RS512,

    /// `ECDSA` using `P-256` (`secp256r1`) curve and `SHA-256` digest
    ES256,

    /// `ECDSA` using `secp256k1` curve and `SHA-256` digest
    ES256K,

    /// `ECDSA` using `P-384` curve and `SHA-284` digest
    ES384,

    /// `ECDSA` using `P-521` curve and `SHA-512` digest
    ES512,

    /// `RSASSA-PSS` using `SHA-256` and MGF1 with SHA-256
    PS256,

    /// `RSASSA-PSS` using `SHA-384` and MGF1 with SHA-384
    PS384,

    /// `RSASSA-PSS` using `SHA-512` and MGF1 with SHA-512
    PS512,

    /// `EdDSA` using Ed25519 curve
    Ed448,

    // EdDSA will likely be deprecated and replaced by Ed25519 (same alg, new name)
    // Ref: https://www.ietf.org/archive/id/draft-ietf-jose-fully-specified-algorithms-13.html#name-fully-specified-jose-algori
    /// `EdDSA` using Ed25519 curve
    EdDSA,

    // post-quantum algs
    // Ref: https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-10#name-new-jose-algorithms
    /// `ML-DSA-44` as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,

    /// `ML-DSA-65` as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,

    /// `ML-DSA-87` as described in US NIST FIPS 204
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}
impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RS256 => write!(f, "RS256"),
            Self::RS384 => write!(f, "RS384"),
            Self::RS512 => write!(f, "RS512"),
            Self::PS256 => write!(f, "PS256"),
            Self::PS384 => write!(f, "PS384"),
            Self::PS512 => write!(f, "PS512"),
            Self::ES256 => write!(f, "ES256"),
            Self::ES256K => write!(f, "ES256K"),
            Self::ES384 => write!(f, "ES384"),
            Self::ES512 => write!(f, "ES512"),
            Self::HS256 => write!(f, "HS256"),
            Self::HS384 => write!(f, "HS384"),
            Self::HS512 => write!(f, "HS512"),
            Self::EdDSA => write!(f, "EdDSA"),
            Self::Ed448 => write!(f, "Ed448"),
            Self::MlDsa44 => write!(f, "ML-DSA-44"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            Self::MlDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::Algorithm;

    #[test]
    fn default_alg_rs256() {
        let alg = Algorithm::default();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn display_repr() {
        assert_eq!(format!("{}", Algorithm::HS256), "HS256");
        assert_eq!(format!("{}", Algorithm::HS384), "HS384");
        assert_eq!(format!("{}", Algorithm::HS512), "HS512");

        assert_eq!(format!("{}", Algorithm::RS256), "RS256");
        assert_eq!(format!("{}", Algorithm::RS384), "RS384");
        assert_eq!(format!("{}", Algorithm::RS512), "RS512");

        assert_eq!(format!("{}", Algorithm::PS256), "PS256");
        assert_eq!(format!("{}", Algorithm::PS384), "PS384");
        assert_eq!(format!("{}", Algorithm::PS512), "PS512");

        assert_eq!(format!("{}", Algorithm::ES256), "ES256");
        assert_eq!(format!("{}", Algorithm::ES256K), "ES256K");
        assert_eq!(format!("{}", Algorithm::ES384), "ES384");
        assert_eq!(format!("{}", Algorithm::ES512), "ES512");

        assert_eq!(format!("{}", Algorithm::EdDSA), "EdDSA");
        assert_eq!(format!("{}", Algorithm::Ed448), "Ed448");

        assert_eq!(format!("{}", Algorithm::MlDsa44), "ML-DSA-44");
        assert_eq!(format!("{}", Algorithm::MlDsa65), "ML-DSA-65");
        assert_eq!(format!("{}", Algorithm::MlDsa87), "ML-DSA-87");
    }
}
