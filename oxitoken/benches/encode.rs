#![allow(clippy::unwrap_used)]
use std::hint::black_box;

use aws_lc_rs::{
    error::Unspecified,
    hmac::{
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        Key as HmacKey,
    },
    rsa::{
        KeyPair as RsaKeyPair,
        KeySize,
    },
    signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P256K1_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED_SIGNING,
        ECDSA_P521_SHA512_FIXED_SIGNING,
        EcdsaKeyPair,
        Ed25519KeyPair,
    },
    unstable::signature::{
        ML_DSA_44_SIGNING,
        ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
};
use criterion::{
    Criterion,
    criterion_group,
    criterion_main,
};
use jsonwebtoken::EncodingKey;
use openssl::{
    ec::{
        EcGroup,
        EcKey,
    },
    nid::Nid,
    pkey::{
        Id,
        PKey,
        PKeyRef,
        Private,
    },
    pkey_ctx::PkeyCtx,
    rsa::Rsa,
};
use oxitoken::{
    Algorithm,
    claims::Exp,
    crypto::openssl::HmacKey as OpensslHmacKey,
    encoding::{
        Signer,
        encode,
    },
    header::Alg,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}
impl Exp for Claims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

fn genkey(alg: Algorithm) -> PKey<Private> {
    fn genrsapss(bits: u32) -> PKey<Private> {
        let mut ctx = PkeyCtx::new_id(Id::RSA_PSS).unwrap();
        ctx.keygen_init().unwrap();
        ctx.set_rsa_keygen_bits(bits).unwrap();
        ctx.keygen().unwrap()
    }

    fn genec(curve: Nid) -> PKey<Private> {
        let key = EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap();
        PKey::from_ec_key(key).unwrap()
    }

    match alg {
        Algorithm::RS256 => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        Algorithm::RS384 => PKey::from_rsa(Rsa::generate(3072).unwrap()).unwrap(),
        Algorithm::RS512 => PKey::from_rsa(Rsa::generate(4096).unwrap()).unwrap(),

        Algorithm::PS256 => genrsapss(2048),
        Algorithm::PS384 => genrsapss(3072),
        Algorithm::PS512 => genrsapss(4096),

        Algorithm::ES256 => genec(Nid::X9_62_PRIME256V1),
        Algorithm::ES256K => genec(Nid::SECP256K1),
        Algorithm::ES384 => genec(Nid::SECP384R1),
        Algorithm::ES512 => genec(Nid::SECP521R1),

        Algorithm::EdDSA => PKey::generate_ed25519().unwrap(),
        Algorithm::Ed448 => PKey::generate_ed448().unwrap(),

        _ => unimplemented!("alg not implemented for benchmarking"),
    }
}

fn pkey_to_jkey(pkey: &PKeyRef<Private>) -> EncodingKey {
    match pkey.id() {
        Id::RSA => EncodingKey::from_rsa_der(pkey.private_key_to_der().unwrap().as_slice()),
        Id::RSA_PSS => {
            // NOTE: aws_lc_rs appears to reject `id-RSASSA-PSS` (OID: 1.2.840.113549.1.1.10) keys,
            // so we just generate a standard Rsa key here since the keypair doesn't
            // need to be the same between benches here. aws_lc itself does support RsaPss keys.
            EncodingKey::from_rsa_der(
                Rsa::generate(pkey.bits())
                    .unwrap()
                    .private_key_to_der()
                    .unwrap()
                    .as_slice(),
            )
        }
        Id::EC => {
            EncodingKey::from_ec_pem(pkey.private_key_to_pem_pkcs8().unwrap().as_slice()).unwrap()
        }
        Id::ED25519 => EncodingKey::from_ed_der(pkey.private_key_to_der().unwrap().as_slice()),
        _ => panic!("not an rsa or ec PKey"),
    }
}

enum AwsKeyType {
    Rsa(RsaKeyPair),
    Ec(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}
impl From<RsaKeyPair> for AwsKeyType {
    fn from(key: RsaKeyPair) -> Self {
        Self::Rsa(key)
    }
}
impl From<EcdsaKeyPair> for AwsKeyType {
    fn from(key: EcdsaKeyPair) -> Self {
        Self::Ec(key)
    }
}
impl From<Ed25519KeyPair> for AwsKeyType {
    fn from(key: Ed25519KeyPair) -> Self {
        Self::Ed25519(key)
    }
}
impl Signer for AwsKeyType {
    type Error = Unspecified;
    fn siglen(&self) -> usize {
        match self {
            Self::Rsa(key) => key.siglen(),
            Self::Ec(key) => key.siglen(),
            Self::Ed25519(key) => key.siglen(),
        }
    }
    fn check_alg(
        &self,
        algorithm: Algorithm,
    ) -> Result<(), oxitoken::encoding::JwtEncodingError<Self::Error>> {
        match self {
            Self::Rsa(key) => key.check_alg(algorithm),
            Self::Ec(key) => key.check_alg(algorithm),
            Self::Ed25519(key) => key.check_alg(algorithm),
        }
    }
    fn sign_jwt(
        &self,
        algorithm: Algorithm,
        jwt: &mut String,
    ) -> Result<(), oxitoken::encoding::JwtEncodingError<Self::Error>> {
        match self {
            Self::Rsa(key) => key.sign_jwt(algorithm, jwt),
            Self::Ec(key) => key.sign_jwt(algorithm, jwt),
            Self::Ed25519(key) => key.sign_jwt(algorithm, jwt),
        }
    }
}

fn pkey_to_akey(pkey: &PKeyRef<Private>) -> AwsKeyType {
    match pkey.id() {
        Id::RSA => RsaKeyPair::from_der(pkey.private_key_to_der().unwrap().as_slice())
            .unwrap()
            .into(),
        // NOTE: aws_lc_rs appears to reject `id-RSASSA-PSS` (OID: 1.2.840.113549.1.1.10) keys,
        // so we just generate a standard new RsaKeyPair here since the keypair doesn't
        // need to be the same between benches here. aws_lc itself does support RsaPss keys.
        Id::RSA_PSS => RsaKeyPair::generate(match pkey.bits() {
            2048 => KeySize::Rsa2048,
            3072 => KeySize::Rsa3072,
            4096 => KeySize::Rsa4096,
            _ => panic!("not a valid aws_lc rsa key size"),
        })
        .unwrap()
        .into(),
        Id::EC => {
            let eck = pkey.ec_key().unwrap();
            let alg = match eck.group().curve_name().unwrap() {
                Nid::X9_62_PRIME256V1 => &ECDSA_P256_SHA256_FIXED_SIGNING,
                Nid::SECP256K1 => &ECDSA_P256K1_SHA256_FIXED_SIGNING,
                Nid::SECP384R1 => &ECDSA_P384_SHA384_FIXED_SIGNING,
                Nid::SECP521R1 => &ECDSA_P521_SHA512_FIXED_SIGNING,
                _ => panic!("unsupported ec curve"),
            };
            EcdsaKeyPair::from_private_key_der(alg, eck.private_key_to_der().unwrap().as_slice())
                .unwrap()
                .into()
        }
        Id::ED25519 => Ed25519KeyPair::from_pkcs8(pkey.private_key_to_pkcs8().unwrap().as_slice())
            .unwrap()
            .into(),
        _ => panic!("unsupported PKey alg for AwsKeyType"),
    }
}

fn genpqkey(alg: Algorithm) -> PqdsaKeyPair {
    match alg {
        Algorithm::MlDsa44 => PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap(),
        Algorithm::MlDsa65 => PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap(),
        Algorithm::MlDsa87 => PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap(),
        _ => panic!("not a pqdsa alg"),
    }
}

fn jalg(alg: Algorithm) -> jsonwebtoken::Algorithm {
    match alg {
        Algorithm::HS256 => jsonwebtoken::Algorithm::HS256,
        Algorithm::HS384 => jsonwebtoken::Algorithm::HS384,
        Algorithm::HS512 => jsonwebtoken::Algorithm::HS512,

        Algorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        Algorithm::RS384 => jsonwebtoken::Algorithm::RS384,
        Algorithm::RS512 => jsonwebtoken::Algorithm::RS512,

        Algorithm::PS256 => jsonwebtoken::Algorithm::PS256,
        Algorithm::PS384 => jsonwebtoken::Algorithm::PS384,
        Algorithm::PS512 => jsonwebtoken::Algorithm::PS512,

        Algorithm::ES256 => jsonwebtoken::Algorithm::ES256,
        Algorithm::ES384 => jsonwebtoken::Algorithm::ES384,

        Algorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,

        // these algs are unsupported by jsonwebtoken as of v10.1.0
        Algorithm::ES256K
        | Algorithm::ES512
        | Algorithm::Ed448
        | Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87 => panic!("jsonwebtoken does not support this alg"),
    }
}

// TODO: break this up?
#[allow(clippy::too_many_lines)]
fn bench_encode(c: &mut Criterion) {
    let sub = "test".into();
    let exp: i64 = 1_865_013_100;
    let claims = Claims { sub, exp };

    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let mut group = c.benchmark_group(format!("{alg}_Enc"));
        group.throughput(criterion::Throughput::Elements(1));

        let header = Header::new(alg);
        let secret = [b'\xff', 64];

        let key = match alg {
            Algorithm::HS256 => OpensslHmacKey::hs256(&secret),
            Algorithm::HS384 => OpensslHmacKey::hs384(&secret),
            Algorithm::HS512 => OpensslHmacKey::hs512(&secret),
            _ => panic!("not an hmac alg"),
        };
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| {
                black_box(encode(black_box(&key), black_box(&header), black_box(&claims)).unwrap())
            });
        });

        let key = HmacKey::new(
            match alg {
                Algorithm::HS256 => HMAC_SHA256,
                Algorithm::HS384 => HMAC_SHA384,
                Algorithm::HS512 => HMAC_SHA512,
                _ => panic!("not an hmac alg"),
            },
            &secret,
        );
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| {
                black_box(encode(black_box(&key), black_box(&header), black_box(&claims)).unwrap())
            });
        });

        let jkey = EncodingKey::from_secret(&secret);
        let jheader = jsonwebtoken::Header {
            alg: jalg(alg),
            ..Default::default()
        };
        group.bench_function("jsonwebtoken", |b| {
            b.iter(|| {
                black_box(
                    jsonwebtoken::encode::<Claims>(
                        black_box(&jheader),
                        black_box(&claims),
                        black_box(&jkey),
                    )
                    .unwrap(),
                );
            });
        });

        group.finish();
    }

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
        let mut group = c.benchmark_group(format!("{alg}_Enc"));
        group.throughput(criterion::Throughput::Elements(1));
        let header = Header::new(alg);

        let key = genkey(alg);
        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| {
                black_box(encode(black_box(&key), black_box(&header), black_box(&claims)).unwrap())
            });
        });

        let akey = pkey_to_akey(&key);
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| {
                black_box(encode(black_box(&akey), black_box(&header), black_box(&claims)).unwrap())
            });
        });

        if !matches!(alg, Algorithm::ES256K | Algorithm::ES512) {
            let jkey = pkey_to_jkey(&key);
            let jheader = jsonwebtoken::Header {
                alg: jalg(alg),
                ..Default::default()
            };
            group.bench_function("jsonwebtoken", |b| {
                b.iter(|| {
                    black_box(
                        jsonwebtoken::encode::<Claims>(
                            black_box(&jheader),
                            black_box(&claims),
                            black_box(&jkey),
                        )
                        .unwrap(),
                    );
                });
            });
        }

        group.finish();
    }

    // Ed448 supported only by oxitoken openssl
    {
        let alg = Algorithm::Ed448;
        let header = Header::new(alg);
        let key = genkey(alg);

        let mut group = c.benchmark_group(format!("{alg}_Enc"));
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("oxitoken_openssl", |b| {
            b.iter(|| {
                black_box(encode(black_box(&key), black_box(&header), black_box(&claims)).unwrap())
            });
        });

        group.finish();
    }

    // PQ Algs supported only by oxitoken aws_lc
    for alg in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let header = Header::new(alg);
        let key = genpqkey(alg);

        let mut group = c.benchmark_group(format!("{alg}_Enc"));
        group.throughput(criterion::Throughput::Elements(1));
        group.bench_function("oxitoken_aws_lc", |b| {
            b.iter(|| {
                black_box(encode(black_box(&key), black_box(&header), black_box(&claims)).unwrap())
            });
        });
        group.finish();
    }
}

criterion_group!(benches, bench_encode);
criterion_main!(benches);
