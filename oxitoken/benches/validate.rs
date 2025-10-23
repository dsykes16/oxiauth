#![allow(clippy::unwrap_used)]
use std::hint::black_box;

use aws_lc_rs::{
    hmac::{
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        Key as AwsLcHmacKey,
    },
    signature::{
        ECDSA_P256_SHA256_FIXED,
        ECDSA_P384_SHA384_FIXED,
        ECDSA_P521_SHA512_FIXED,
        ED25519,
        ParsedPublicKey,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256,
        RSA_PSS_2048_8192_SHA384,
        RSA_PSS_2048_8192_SHA512,
        UnparsedPublicKey,
        VerificationAlgorithm,
    },
    unstable::signature::{
        ML_DSA_44_SIGNING,
        ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
};
use base64_simd::URL_SAFE_NO_PAD as b64;
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
    ec::{
        EcGroup,
        EcKey,
    },
    nid::Nid,
    pkey::{
        HasPublic,
        Id,
        PKey,
        PKeyRef,
        Private,
        Public,
    },
    pkey_ctx::PkeyCtx,
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
    crypto::{
        aws_lc::AwsLcVerificationKey,
        openssl::HmacKey as OsslHmacKey,
    },
    encoding::encode,
    header::{
        Alg,
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
impl Header {
    #[must_use]
    pub fn kid(&self) -> &str {
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
impl Claims {
    #[must_use]
    pub fn sub(&self) -> &str {
        &self.sub
    }
}

fn validate_spiffe(c: &mut Criterion) {
    let mut group = c.benchmark_group("SPIFFE_RS256");
    let jwt = b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImVrSVp0ZHhEcFNJcmNqWVBFdWxldjVjcHRXSlljeHJ3IiwidHlwIjoiSldUIn0.eyJhdWQiOlsianNvbndlYnRva2VudGVzdCJdLCJleHAiOjE3NjAzMzcxMTcsImlhdCI6MTc2MDMzNjgxNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvdGVzdHNlcnZpY2UifQ.JrQP9zOcbDk_wJqYRn33VdX72vqVMS57heRjucyMVJjEbLaW4BWIwNsoGfnvX8uyKS6BYhaOzwQHHFX8sRXpEGPJ3LBrbnYzBZx3dCwyEKagygEbo2b858s8UoKUMNf_Kw4V_df8dyHvYl_XudK6vScrxknnClx7ccpshp1B4po0peDs25_4Ujdmz5a-WO141eIy0G5o0B2lqWRHIpUbbTKosdxuuxlRHVKvd3a0zZl68Vs4Z5pbzWa5vW87pSsIlZy_7joGjM11w8tNRDkwufZMBwREd-_ZyPRIS3CNHAuQV90W_jC3cy2U52QoHbXkVYIbzgr9Bo76_blrq0FJ-Q";
    group.throughput(Throughput::Bytes(jwt.len() as u64));

    group.bench_function("oxitoken_aws_lc", |b| {
        let key = include_bytes!("spiffe.der");
        let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key);
        let key = key.parse().unwrap();
        let key = AwsLcVerificationKey::try_from(key).unwrap();
        let expected_aud = "jsonwebtokentest";
        let validator: ValidationPipeline<Header, Claims, StaticKeyProvider<_>> =
            ValidationPipeline::builder(key.into())
                .with_audience_validator(expected_aud)
                .with_issued_at_validator()
                .with_type_validator(["JWT", "JOSE"])
                .build();

        b.iter(|| black_box(validator.verify(black_box(jwt)).unwrap()));
    });

    group.bench_function("jsonwebtoken_validate_spiffe", |b| {
        let n = b64.decode_to_vec(b"pJVae_f7hiDZjGNsjWTLRzCMJ6KNhTTto7eBU4TSbjaDcus2NsmrQItbeuR92qrDY_HyOPQoniSqz9aOfJ46Sp9axKUhrx4m60Yb7t1zFWKvzgniv6OFNwxyh8_5cdsGun47Dj-zBJDz_oHW6aDeVaHgV26jxIFp0ph4iugXH5pKP8hZDKoPJZdQ-98HgOHJFxeLVeB4IfTewdEoiOXBHENcNDaGb50vxG6nMMetl4XgHe4yIksOFOD0jGruryP4e-HKlXbIJVTQEZMxoZClPTFKr0hv778LFCVc4arQvXgH0MLIToW145YH6DDPiKBylW8LKSAVHzbhPLAdVtjXJw").unwrap();
        let e = b64.decode_to_vec(b"AQAB").unwrap();
        let decoding_key = DecodingKey::from_rsa_raw_components(&n, &e);
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_audience(&["jsonwebtokentest"]);

        b.iter(|| {
            jsonwebtoken::decode::<Claims>(
                black_box(&jwt),
                black_box(&decoding_key),
                black_box(&validation),
            )
            .unwrap();
        });
    });
}

fn claims() -> Claims {
    let iat: i64 = 0;
    let exp: i64 = 1_865_013_100;
    let sub = "test".into();
    let aud = vec!["oxitoken-test".into()];
    Claims { aud, exp, iat, sub }
}

fn header(alg: Algorithm) -> Header {
    let typ = "JWT".into();
    let kid = "testkey".into();
    Header { alg, kid, typ }
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

fn jwst_val(alg: jsonwebtoken::Algorithm) -> Validation {
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp", "aud", "sub", "iat"]);
    validation.set_audience(&["oxitoken-test"]);
    // `typ` validation does not appear to be possible in [`jsonwebtoken`] at this time
    validation
}

fn genkey(alg: Algorithm) -> PKey<Private> {
    match alg {
        Algorithm::RS256 => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        Algorithm::RS384 => PKey::from_rsa(Rsa::generate(3072).unwrap()).unwrap(),
        Algorithm::RS512 => PKey::from_rsa(Rsa::generate(4096).unwrap()).unwrap(),

        Algorithm::PS256 => genrsapss(256),
        Algorithm::PS384 => genrsapss(384),
        Algorithm::PS512 => genrsapss(512),

        Algorithm::ES256 => genec(Nid::X9_62_PRIME256V1),
        Algorithm::ES256K => genec(Nid::SECP256K1),
        Algorithm::ES384 => genec(Nid::SECP384R1),
        Algorithm::ES512 => genec(Nid::SECP521R1),

        Algorithm::EdDSA => PKey::generate_ed25519().unwrap(),
        Algorithm::Ed448 => PKey::generate_ed448().unwrap(),

        _ => unimplemented!("alg not implemented for benchmarking"),
    }
}

fn genec(curve: Nid) -> PKey<Private> {
    let key = EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap();
    PKey::from_ec_key(key).unwrap()
}

fn genrsapss(dlen: usize) -> PKey<Private> {
    let mut ctx = PkeyCtx::new_id(Id::RSA_PSS).unwrap();
    ctx.keygen_init().unwrap();
    // SAFETY: 4096-bits is the current max RSA key size we support
    #[allow(clippy::cast_possible_truncation)]
    ctx.set_rsa_keygen_bits((dlen * 8) as u32).unwrap();
    ctx.keygen().unwrap()
}

fn awshkey(alg: Algorithm, secret: &[u8]) -> AwsLcHmacKey {
    let kalg = match alg {
        Algorithm::HS256 => HMAC_SHA256,
        Algorithm::HS384 => HMAC_SHA384,
        Algorithm::HS512 => HMAC_SHA512,
        _ => panic!("not an hmac alg"),
    };
    AwsLcHmacKey::new(kalg, secret)
}

fn pkey_to_vkey<T>(pkey: &PKeyRef<T>) -> ParsedPublicKey
where
    T: HasPublic,
{
    let kalg: &'static dyn VerificationAlgorithm = match (pkey.id(), pkey.bits()) {
        (Id::RSA, 2048) => &RSA_PKCS1_2048_8192_SHA256,
        (Id::RSA, 3072) => &RSA_PKCS1_2048_8192_SHA384,
        (Id::RSA, 4096) => &RSA_PKCS1_2048_8192_SHA512,
        (Id::RSA_PSS, 2048) => &RSA_PSS_2048_8192_SHA256,
        (Id::RSA_PSS, 3072) => &RSA_PSS_2048_8192_SHA384,
        (Id::RSA_PSS, 4096) => &RSA_PSS_2048_8192_SHA512,
        (Id::EC, 256) => &ECDSA_P256_SHA256_FIXED,
        (Id::EC, 384) => &ECDSA_P384_SHA384_FIXED,
        (Id::EC, 521) => &ECDSA_P521_SHA512_FIXED,

        (Id::ED25519, _) => &ED25519,
        _ => panic!("unsupported vkey alg"),
    };
    ParsedPublicKey::new(kalg, pkey.public_key_to_der().unwrap().as_slice()).unwrap()
    //.try_into()
    //.unwrap()
}

fn pkey_to_jkey<T>(pkey: &PKeyRef<T>) -> DecodingKey
where
    T: HasPublic,
{
    match pkey.id() {
        Id::RSA | Id::RSA_PSS => {
            DecodingKey::from_rsa_der(pkey.public_key_to_der().unwrap().as_slice())
        }
        Id::EC => DecodingKey::from_ec_der(pkey.public_key_to_der().unwrap().as_slice()),
        Id::ED25519 => DecodingKey::from_ed_der(pkey.public_key_to_der().unwrap().as_slice()),
        _ => panic!("not an rsa or ec PKey"),
    }
}

const fn jalg(alg: Algorithm) -> Option<jsonwebtoken::Algorithm> {
    match alg {
        Algorithm::HS256 => Some(jsonwebtoken::Algorithm::HS256),
        Algorithm::HS384 => Some(jsonwebtoken::Algorithm::HS384),
        Algorithm::HS512 => Some(jsonwebtoken::Algorithm::HS512),

        Algorithm::RS256 => Some(jsonwebtoken::Algorithm::RS256),
        Algorithm::RS384 => Some(jsonwebtoken::Algorithm::RS384),
        Algorithm::RS512 => Some(jsonwebtoken::Algorithm::RS512),

        Algorithm::PS256 => Some(jsonwebtoken::Algorithm::PS256),
        Algorithm::PS384 => Some(jsonwebtoken::Algorithm::PS384),
        Algorithm::PS512 => Some(jsonwebtoken::Algorithm::PS512),

        Algorithm::ES256 => Some(jsonwebtoken::Algorithm::ES256),
        Algorithm::ES384 => Some(jsonwebtoken::Algorithm::ES384),

        Algorithm::EdDSA => Some(jsonwebtoken::Algorithm::EdDSA),

        // these algs are unsupported by jsonwebtoken as of v10.1.0
        Algorithm::ES256K
        | Algorithm::ES512
        | Algorithm::Ed448
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87 => None,
    }
}

// TODO: break this up?
#[allow(clippy::too_many_lines)]
fn validate(c: &mut Criterion) {
    for alg in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
        Algorithm::ES256,
        Algorithm::ES384,
        Algorithm::EdDSA,
    ] {
        let mut group = c.benchmark_group(alg.to_string());
        let key = genkey(alg);
        let jwt = encode(&key, &header(alg), &claims()).unwrap();
        group.throughput(Throughput::Bytes(jwt.len() as u64));

        let pubkey = pkey_to_vkey(&key);
        let validator = oxi_val(pubkey);
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        let pubkey: PKey<Public> =
            PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
        let validator = oxi_val(pubkey);
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        if let Some(alg) = jalg(alg) {
            let pubkey = pkey_to_jkey(&key);
            let validation = jwst_val(alg);
            group.bench_function("jsonwebtoken", |b| {
                b.iter(|| {
                    black_box(
                        jsonwebtoken::decode::<Claims>(
                            black_box(&jwt),
                            black_box(&pubkey),
                            black_box(&validation),
                        )
                        .unwrap(),
                    );
                });
            });
        }
        group.finish();
    }

    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let mut group = c.benchmark_group(alg.to_string());
        let secret = [b'\xFF'; 64];
        let key = match alg {
            Algorithm::HS256 => OsslHmacKey::hs256(&secret),
            Algorithm::HS384 => OsslHmacKey::hs384(&secret),
            Algorithm::HS512 => OsslHmacKey::hs512(&secret),
            _ => panic!("not an hmac alg"),
        };
        let jwt = encode(&key, &header(alg), &claims()).unwrap();
        group.throughput(Throughput::Bytes(jwt.len() as u64));

        let akey = awshkey(alg, &secret);
        let validator = oxi_val(akey);
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        let validator = oxi_val(key);
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        let jkey = DecodingKey::from_secret(&secret);
        let jalg = jalg(alg).unwrap();
        let validation = jwst_val(jalg);
        group.bench_function("jsonwebtoken", |b| {
            b.iter(|| {
                black_box(
                    jsonwebtoken::decode::<Claims>(
                        black_box(&jwt),
                        black_box(&jkey),
                        black_box(&validation),
                    )
                    .unwrap(),
                );
            });
        });
        group.finish();
    }

    // Ed448
    {
        let alg = Algorithm::Ed448;
        let mut group = c.benchmark_group(alg.to_string());
        let key = genkey(alg);
        let jwt = encode(&key, &header(alg), &claims()).unwrap();
        group.throughput(Throughput::Bytes(jwt.len() as u64));

        let validator = oxi_val(key);
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        // NOTE: aws_lc and jsonwebtoken don't support Ed448

        group.finish();
    }

    for alg in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let mut group = c.benchmark_group(alg.to_string());
        let key = match alg {
            Algorithm::MlDsa44 => PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap(),
            Algorithm::MlDsa65 => PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap(),
            Algorithm::MlDsa87 => PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap(),
            _ => panic!("not a post-quantum alg"),
        };
        let jwt = encode(&key, &header(alg), &claims()).unwrap();
        group.throughput(Throughput::Bytes(jwt.len() as u64));

        let pubkey: AwsLcVerificationKey = (&key).try_into().unwrap();
        let validator = oxi_val(pubkey);
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| black_box(validator.verify(black_box(jwt.as_bytes())).unwrap()));
        });

        // NOTE: rust-openssl does not yet expose PQ algs; jsonwebtoken does not support PQ algs

        group.finish();
    }
}

criterion_group!(benches, validate, validate_spiffe);
criterion_main!(benches);
