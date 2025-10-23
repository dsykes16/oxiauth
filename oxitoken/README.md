# OxiToken

`oxitoken` strives to be the fastest JWT encoding/decoding/validation library
while simulteneously providing the best developer experience and extensibility.

- Custom header and claims structs, no stringly-typed `extras` HashMap here
- Custom `KeyProvider` support
  - A `LocalKeystore` implementation is provided that resolves keys via `kid`
  - If that doesn't fit your use-case, implement your own `KeyProvider`, which
    can resolve keys via any abitrary header or claim field, even custom ones
- Crypto backend agnostic
  - Reference implementations using `aws-lc-rs` and `openssl` are provided
    - `Signer` and `VerificationKey` traits permit using your own crypto
      backend (e.g. `botan-rs`, `ring`, HSMs, etc.)
    - Built-in providers can be fully disabled with feature flags
- Supports _all_ the IANA registered JWS algorithms
  - HMAC: `HS256`, `HS384`, `HS512`
  - RSA: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`
  - ECDSA: `ES256`, `ES384`, `ES512`
  - EdDSA: `EdDSA` (i.e. `Ed25519`) and `Ed448`
  - Post-Quantum algorithms: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`

## Benchmarks

### Encoding Performance

| Algorithm | oxitoken | jsonwebtoken | % faster |
|---|---:|---:|---:|
| HS256 | 312.45 ns | 638.67 ns | 51.08 % |
| HS384 | 417.19 ns | 856.24 ns | 51.28 % |
| HS512 | 422.99 ns | 862.96 ns | 50.98 % |
| RS256 | 480.22 µs | 762.61 µs | 37.03 % |
| RS384 | 1525.74 µs | 2056.15 µs | 25.8 % |
| RS512 | 3234.4 µs | 4051.46 µs | 20.17 % |
| PS256 | 480.72 µs | 765.89 µs | 37.23 % |
| PS384 | 1529.31 µs | 2098.04 µs | 27.11 % |
| PS512 | 3252.92 µs | 4072.99 µs | 20.13 % |
| ES256 | 16.47 µs | 25.57 µs | 35.58 % |
| ES384 | 69.61 µs | 112.13 µs | 37.92 % |
| EdDSA | 6.51 µs | 12.48 µs | 47.85 % |
| ML-DSA-44 | 140.91 µs |  |  |
| ML-DSA-65 | 230.96 µs |  |  |
| ML-DSA-87 | 284.98 µs |  |  |

### Validation Performance

| Algorithm | oxitoken | jsonwebtoken | % faster |
|---|---:|---:|---:|
| HS256 | 623.51 ns | 1.7 µs | 63.28 % |
| HS384 | 788.75 ns | 2 µs | 60.55 % |
| HS512 | 789.81 ns | 2.05 µs | 61.48 % |
| RS256 | 13.48 µs | 17.13 µs | 21.35 % |
| RS384 | 26.87 µs | 32.88 µs | 18.28 % |
| RS512 | 45.97 µs | 53.9 µs | 14.71 % |
| PS256 | 13.34 µs | 17.39 µs | 23.3 % |
| PS384 | 27.77 µs | 33.55 µs | 17.21 % |
| PS512 | 46.92 µs | 54.86 µs | 14.48 % |
| ES256 | 42.98 µs | 44.55 µs | 3.52 % |
| ES384 | 163.61 µs | 165.55 µs | 1.17 % |
| EdDSA | 27.89 µs | 28.98 µs | 3.77 % |
| ML-DSA-44 | 39.19 µs |  |  |
| ML-DSA-65 | 63.38 µs |  |  |
| ML-DSA-87 | 104.22 µs |  |  |

Comparative benchmarks above were ran with `aws-lc-rs` backend for both `oxitoken` and `jsonwebtoken`.
`openssl` is slightly slower than `aws-lc-rs` across the board, and `rust_crypto` is substantially slower.

## Example

```rust
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
```
