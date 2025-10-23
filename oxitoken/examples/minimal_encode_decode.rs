#![allow(clippy::unwrap_used)]
use aws_lc_rs::signature::{
    ED25519,
    Ed25519KeyPair,
    KeyPair,
    ParsedPublicKey,
};
use oxitoken::{
    Algorithm,
    claims::{
        Exp,
        Iss,
    },
    encoding::encode,
    header::Alg,
    validation::{
        StaticKeyProvider,
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
    exp: i64,
}
impl Claims {
    fn new(iss: impl Into<String>) -> Self {
        Self {
            iss: iss.into(),
            exp: 0,
        }
    }
}
impl Iss for Claims {
    fn iss(&self) -> &str {
        &self.iss
    }
}
impl Exp for Claims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

fn make_key() -> Ed25519KeyPair {
    Ed25519KeyPair::generate().unwrap()
}

fn make_parsed_public_key(key: &Ed25519KeyPair) -> ParsedPublicKey {
    ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap()
}

fn main() {
    let header = Header::new(Algorithm::EdDSA);
    let claims = Claims::new("oxitoken.example.org");
    let key = make_key();
    let jwt = encode(&key, &header, &claims).unwrap();
    println!("JWT: {jwt}");

    let pubkey = make_parsed_public_key(&key);
    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(pubkey.into())
            .with_issuer_validator("oxitoken.example.org")
            .with_expiration_validator()
            .build();

    let (decoded_header, decoded_claims) = validator.verify(jwt.as_bytes()).unwrap();

    assert_eq!(decoded_header, header);
    assert_eq!(decoded_claims, claims);

    println!("JWT validated successfully");

    // an alternative that allows the compiler to infer the generic types,
    // permitting omittance of the turbofish.
    let pubkey = StaticKeyProvider::from(make_parsed_public_key(&key));
    let validator = ValidationPipeline::builder(pubkey)
        .with_issuer_validator("oxitoken.example.org")
        .build();
    let (decoded_header, decoded_claims): (Header, Claims) =
        validator.verify(jwt.as_bytes()).unwrap();

    assert_eq!(decoded_header, header);
    assert_eq!(decoded_claims, claims);
}
