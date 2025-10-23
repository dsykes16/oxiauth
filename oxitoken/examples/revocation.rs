#![allow(clippy::unwrap_used)]
use std::{
    collections::HashSet,
    sync::{
        Arc,
        Mutex,
    },
};

use aws_lc_rs::signature::{
    ED25519,
    Ed25519KeyPair,
    KeyPair,
    ParsedPublicKey,
};
use oxitoken::{
    Algorithm,
    claims::Jti,
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
    jti: String,
}
impl Claims {
    fn new(jti: impl Into<String>) -> Self {
        Self { jti: jti.into() }
    }
}
impl Jti for Claims {
    fn jti(&self) -> &str {
        &self.jti
    }
}

// ANCHOR: impl
pub struct RevocationValidator {
    revocation_list: Arc<Mutex<HashSet<String>>>,
}
impl RevocationValidator {
    const fn new(revocation_list: Arc<Mutex<HashSet<String>>>) -> Self {
        Self { revocation_list }
    }
}
impl TokenValidator<Header, Claims> for RevocationValidator {
    fn validate(&self, _header: &Header, claims: &Claims) -> Result<(), JwtError> {
        self.revocation_list.lock().map_or(
            Err(JwtError::CustomValidationError(
                "revocation list lock not acquired",
            )),
            |rl| {
                if rl.contains(claims.jti()) {
                    Err(JwtError::CustomValidationError("token revoked"))
                } else {
                    Ok(())
                }
            },
        )
    }
}
// ANCHOR_END: impl

fn main() {
    let key = Ed25519KeyPair::generate().unwrap();
    let pubkey = ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap();

    let header = Header::new(Algorithm::EdDSA);
    let claims = Claims::new("fake-jti");

    let jwt = encode(&key, &header, &claims).unwrap();

    // ANCHOR: usage

    let revocation_list = Arc::new(Mutex::new(HashSet::<String>::new()));
    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(pubkey.into())
            .with(RevocationValidator::new(revocation_list.clone()))
            .build();

    let (_, _) = validator.verify(jwt.as_bytes()).unwrap();

    revocation_list.lock().unwrap().insert("fake-jti".into());

    let err = validator.verify(jwt.as_bytes()).unwrap_err();

    assert!(matches!(
        err,
        JwtError::CustomValidationError("token revoked")
    ));

    // ANCHOR_END: usage
}
