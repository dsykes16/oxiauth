#![allow(clippy::unwrap_used)]
use std::{
    fmt::Display,
    hint::black_box,
};

use aws_lc_rs::signature::{
    ParsedPublicKey,
    RSA_PKCS1_2048_8192_SHA256,
};
use criterion::{
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use jsonwebtoken::{
    DecodingKey,
    Validation,
};
use openssl::{
    pkey::PKey,
    rsa::Rsa,
};
use oxitoken::{
    Algorithm,
    claims::{
        Aud,
        Exp,
        Iat,
        Sub,
    },
    crypto::aws_lc::AwsLcVerificationKey,
    header::{
        Alg,
        Kid,
        Typ,
    },
    validation::{
        StaticKeyProvider,
        ValidationPipeline,
        VerificationKey,
    },
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    alg: Algorithm,
    kid: String,
    typ: String,
}
impl Kid for Header {
    fn kid(&self) -> &str {
        &self.kid
    }
}
impl Alg for Header {
    fn alg(&self) -> Algorithm {
        self.alg
    }
}
impl Typ for Header {
    type Type = str;
    fn typ(&self) -> &str {
        &self.typ
    }
}

// NOTE: [`Clone`] is NOT required by [`oxitoken-jwt`] but is required by [`jsonwebtoken`]
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    sub: String,
}
impl Aud for Claims {
    fn aud(&self) -> impl Iterator<Item = impl AsRef<str>> {
        self.aud.as_slice().iter()
    }
}
impl Iat for Claims {
    fn iat(&self) -> i64 {
        self.iat
    }
}
impl Exp for Claims {
    fn exp(&self) -> i64 {
        self.exp
    }
}
impl Sub for Claims {
    fn sub(&self) -> &str {
        &self.sub
    }
}

fn claims() -> Claims {
    let iat: i64 = 0;
    let exp: i64 = 1_865_013_100;
    let sub = "test".into();
    let aud = vec!["oxitoken-test".into()];
    Claims { aud, exp, iat, sub }
}

fn oxi_val<T>(key: T) -> ValidationPipeline<Header, Claims, StaticKeyProvider<T>>
where
    T: VerificationKey + Send + Sync + 'static,
{
    ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(key.into())
        .with_expiration_validator()
        .with_audience_validator("oxitoken-test")
        .with_type_validator(["JWT", "JOSE"])
        .build()
}

fn oxi_val_with_max_size<T>(key: T) -> ValidationPipeline<Header, Claims, StaticKeyProvider<T>>
where
    T: VerificationKey + Send + Sync + 'static,
{
    ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(key.into())
        .with_max_size(16 * 1024)
        .with_expiration_validator()
        .with_audience_validator("oxitoken-test")
        .with_type_validator(["JWT", "JOSE"])
        .build()
}

fn jwst_val(alg: jsonwebtoken::Algorithm) -> Validation {
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "aud", "sub", "iat"]);
    validation.set_audience(&["oxitoken-test"]);
    // `typ` validation does not appear to be possible in [`jsonwebtoken`] at this time
    validation
}

#[derive(Debug, Clone, Copy)]
enum Size {
    /// yields `8_000` byte JWT
    Jwt8K,
    /// yields `16_000` byte JWT
    Jwt16K,
    /// yields `61_088` byte JWT
    /// Envoy/Istio proxy default max header size is `61_440`
    Jwt60K,
    /// yields `130_908` byte JWT
    /// Cloudflare proxy max header size is `131_072`
    Jwt128K,
    /// yields `3_999_996` byte JWT
    Jwt4M,
}
impl Display for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt8K => write!(f, "8K"),
            Self::Jwt16K => write!(f, "16K"),
            Self::Jwt60K => write!(f, "60K"),
            Self::Jwt128K => write!(f, "128K"),
            Self::Jwt4M => write!(f, "4M"),
        }
    }
}

fn mkadv(sz: Size) -> String {
    const CS: &str = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    const CSL: u64 = CS.len() as u64;
    fn gnc(n: u64) -> char {
        CS.chars().nth(n.try_into().unwrap()).unwrap()
    }
    fn nstr(sz: u64, out: &mut String) -> u64 {
        if sz < CSL {
            out.push(gnc(sz));
            0
        } else {
            let rem = sz.rem_euclid(CSL);
            out.push(CS.chars().nth(rem.try_into().unwrap()).unwrap());
            nstr(sz.div_euclid(CSL), out)
        }
    }

    let mut header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        typ: Some("JWT".into()),
        ..Default::default()
    };
    let hc = match sz {
        Size::Jwt8K => 718,
        Size::Jwt16K => 1468,
        Size::Jwt60K => 5695,
        Size::Jwt128K => 11821,
        Size::Jwt4M => 334_245,
    };
    for i in 0..hc {
        let mut s = String::new();
        nstr(i, &mut s);
        header.extras.insert(s, String::new());
    }
    let key = jsonwebtoken::EncodingKey::from_rsa_der(include_bytes!("rs256_private.der"));
    let jwt = jsonwebtoken::encode(&header, &claims(), &key).unwrap();
    match sz {
        Size::Jwt8K => assert_eq!(jwt.len(), 8_000),
        Size::Jwt16K => assert_eq!(jwt.len(), 16_000),
        Size::Jwt60K => assert_eq!(jwt.len(), 61_088),
        Size::Jwt128K => assert_eq!(jwt.len(), 130_908),
        Size::Jwt4M => assert_eq!(jwt.len(), 3_999_996),
    }
    jwt
}

fn adversarial(c: &mut Criterion) {
    for sz in [
        Size::Jwt8K,
        Size::Jwt16K,
        Size::Jwt60K,
        Size::Jwt128K,
        Size::Jwt4M,
    ] {
        let mut group = c.benchmark_group(format!("Adversarial JWT ({sz})"));
        let jwt = mkadv(sz);
        group.throughput(Throughput::Bytes(jwt.len() as u64));

        // NOTE: the pubkey here doesn't match the private key, that's intentional
        // this test is meant to simulate a bad actor sending oversized JWTs with
        // bad signatures as a means of DDoS amplification.
        let pubkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let validator = oxi_val_with_max_size(
            AwsLcVerificationKey::try_from(
                ParsedPublicKey::new(
                    &RSA_PKCS1_2048_8192_SHA256,
                    pubkey.public_key_to_der().unwrap().as_slice(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        group.bench_function("oxitoken_with_size_validator_aws_lc", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap_err()));
        });

        let validator = oxi_val(
            AwsLcVerificationKey::try_from(
                ParsedPublicKey::new(
                    &RSA_PKCS1_2048_8192_SHA256,
                    pubkey.public_key_to_der().unwrap().as_slice(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap_err()));
        });

        let validator = oxi_val(pubkey.clone());
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap_err()));
        });

        let jkey = DecodingKey::from_rsa_der(pubkey.public_key_to_der().unwrap().as_slice());
        let validation = jwst_val(jsonwebtoken::Algorithm::RS256);
        group.bench_function("jsonwebtoken", |b| {
            b.iter(|| {
                black_box(
                    jsonwebtoken::decode::<Claims>(
                        black_box(&jwt),
                        black_box(&jkey),
                        black_box(&validation),
                    )
                    .unwrap_err(),
                );
            });
        });
        group.finish();
    }
}

criterion_group!(benches, adversarial);
criterion_main!(benches);
