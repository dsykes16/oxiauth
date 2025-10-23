#![allow(clippy::unwrap_used)]
use aws_lc_rs::{
    rsa::KeySize,
    signature::RsaKeyPair,
};
use oxitoken::{
    Algorithm,
    claims::Iss,
    encoding::encode,
    header::Alg,
};

#[derive(serde::Deserialize, serde::Serialize)]
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

#[derive(serde::Deserialize, serde::Serialize)]
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

fn make_rsa_key() -> RsaKeyPair {
    RsaKeyPair::generate(KeySize::Rsa2048).unwrap()
}

fn main() {
    let header = Header::new(Algorithm::RS256);
    let claims = Claims::new("oxitoken.example.org");
    let key = make_rsa_key();

    let jwt = encode(&key, &header, &claims).unwrap();
    println!("JWT: {jwt}");
}
