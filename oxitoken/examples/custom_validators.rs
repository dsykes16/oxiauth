#![allow(clippy::unwrap_used)]
use std::collections::HashSet;

use aws_lc_rs::signature::{
    ED25519,
    Ed25519KeyPair,
    KeyPair,
    ParsedPublicKey,
};
use oxitoken::{
    Algorithm,
    claims::Iss,
    encoding::encode,
    error::JwtError,
    header::Alg,
    validation::{
        StaticKeyProvider,
        TokenValidator,
        ValidationPipeline,
    },
};

// NOTE: Debug, PartialEq, and Eq are only required for the assertions in this
// example code and are not a requirement of oxitoken.
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct Header {
    alg: Algorithm,
}
impl Header {
    const fn new(alg: Algorithm) -> Self {
        Self { alg }
    }
}
impl Alg for Header {
    fn alg(&self) -> Algorithm {
        self.alg
    }
}

// NOTE: Debug, PartialEq, and Eq are only required for the assertions in this
// example code and are not a requirement of oxitoken.
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct Claims {
    iss: String,
}
impl Claims {
    fn new(iss: impl Into<String>) -> Self {
        Self { iss: iss.into() }
    }
}
impl Iss for Claims {
    fn iss(&self) -> &str {
        &self.iss
    }
}

// ANCHOR: impl
pub struct IssuerValidator {
    accepted_issuers: HashSet<String>,
}
impl IssuerValidator {
    pub(crate) fn new(accepted_issuers: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let accepted_issuers = accepted_issuers.into_iter().map(Into::into).collect();
        Self { accepted_issuers }
    }
}
impl<H, C> TokenValidator<H, C> for IssuerValidator
where
    C: Iss,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if self.accepted_issuers.contains(claims.iss()) {
            Ok(())
        } else {
            Err(JwtError::WrongIssuer)
        }
    }
}
// ANCHOR_END: impl

fn main() {
    let key = Ed25519KeyPair::generate().unwrap();
    let pubkey = ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap();

    let header = Header::new(Algorithm::EdDSA);
    let claims = Claims::new("oxitoken.example.org");

    let jwt = encode(&key, &header, &claims).unwrap();

    // ANCHOR: usage
    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(pubkey.into())
            .with(IssuerValidator::new([
                "oxitoken.example.org",
                "jwt.example.org",
            ]))
            .build();
    // ANCHOR_END: usage

    let (decoded_header, decoded_claims) = validator.verify(jwt.as_bytes()).unwrap();

    assert_eq!(decoded_header, header);
    assert_eq!(decoded_claims, claims);

    println!("JWT validated successfully");
}
