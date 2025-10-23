#![allow(clippy::unwrap_used)]
use openssl::{
    ec::{
        EcGroup,
        EcKey,
    },
    error::ErrorStack,
    nid::Nid,
    pkey::{
        Id,
        PKey,
        Private,
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
        Iss,
        Nbf,
        Sub,
    },
    crypto::openssl::HmacKey,
    encoding::{
        JwtEncodingError,
        Signer,
        encode,
    },
    error::JwtError,
    header::{
        Alg,
        Typ,
    },
    validation::{
        StaticKeyProvider,
        TokenValidator,
        ValidationPipeline,
        VerificationKey,
    },
};

#[derive(Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Header {
    alg: Algorithm,
    typ: String,
}
impl Alg for Header {
    fn alg(&self) -> Algorithm {
        self.alg
    }
}
impl Typ for Header {
    type Type = str;
    fn typ(&self) -> &Self::Type {
        &self.typ
    }
}
impl From<Header> for jsonwebtoken::Header {
    fn from(value: Header) -> Self {
        Self {
            alg: map_jswt_alg(value.alg),
            ..Default::default()
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: i64,
    iat: i64,
    nbf: i64,
    custom_claim: Vec<String>,
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
impl Iss for Claims {
    fn iss(&self) -> &str {
        &self.iss
    }
}
impl Aud for Claims {
    fn aud(&self) -> impl Iterator<Item = impl AsRef<str>> {
        self.aud.iter()
    }
}
impl Nbf for Claims {
    fn nbf(&self) -> i64 {
        self.nbf
    }
}
impl Iat for Claims {
    fn iat(&self) -> i64 {
        self.iat
    }
}

fn header(alg: Algorithm) -> Header {
    Header {
        alg,
        typ: "JWT".into(),
    }
}

fn claims() -> Claims {
    Claims {
        sub: "subscriber@example.org".into(),
        exp: 1_865_013_100,
        iat: 0,
        nbf: 17_760_704,
        iss: "issuer.example.org".into(),
        aud: vec!["oxitoken".into(), "jsonwebtoken".into()],
        custom_claim: vec!["oxitoken".into(), "is".into(), "awesome".into()],
    }
}

struct CustomClaimValidator;
impl CustomClaimValidator {
    const fn new() -> Self {
        Self {}
    }
}
impl TokenValidator<Header, Claims> for CustomClaimValidator {
    fn validate(&self, _: &Header, claims: &Claims) -> Result<(), JwtError> {
        if claims.custom_claim.join(" ") == "oxitoken is awesome" {
            Ok(())
        } else {
            Err(JwtError::CustomValidationError(
                r#"'custom_claim' was not '["oxitoken", "is", "awesome"]'"#,
            ))
        }
    }
}

fn genrsa(bits: u32) -> PKey<Private> {
    let key = Rsa::generate(bits).unwrap();
    PKey::from_rsa(key).unwrap()
}

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

enum Key {
    PKey(PKey<Private>),
    Hmac(HmacKey),
}
impl From<PKey<Private>> for Key {
    fn from(key: PKey<Private>) -> Self {
        Self::PKey(key)
    }
}
impl From<HmacKey> for Key {
    fn from(key: HmacKey) -> Self {
        Self::Hmac(key)
    }
}
impl Signer for Key {
    type Error = ErrorStack;
    fn check_alg(&self, algorithm: Algorithm) -> Result<(), JwtEncodingError<Self::Error>> {
        match self {
            Self::Hmac(key) => key.check_alg(algorithm),
            Self::PKey(key) => key.check_alg(algorithm),
        }
    }
    fn sign_jwt(
        &self,
        algorithm: Algorithm,
        jwt: &mut String,
    ) -> Result<(), JwtEncodingError<Self::Error>> {
        match self {
            Self::Hmac(key) => key.sign_jwt(algorithm, jwt),
            Self::PKey(key) => key.sign_jwt(algorithm, jwt),
        }
    }
    fn siglen(&self) -> usize {
        match self {
            Self::Hmac(key) => key.siglen(),
            Self::PKey(key) => key.siglen(),
        }
    }
}
impl VerificationKey for Key {
    fn alg(&self) -> Option<Algorithm> {
        match self {
            Self::Hmac(key) => key.alg(),
            Self::PKey(key) => key.alg(),
        }
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        match self {
            Self::Hmac(key) => key.verify(message, signature),
            Self::PKey(key) => key.verify(message, signature),
        }
    }
}

fn genkey(alg: Algorithm, hmac_char: u8) -> Key {
    match alg {
        Algorithm::RS256 => genrsa(2048).into(),
        Algorithm::RS384 => genrsa(3072).into(),
        Algorithm::RS512 => genrsa(4096).into(),
        Algorithm::PS256 => genrsapss(2048).into(),
        Algorithm::PS384 => genrsapss(3072).into(),
        Algorithm::PS512 => genrsapss(4096).into(),
        Algorithm::ES256 => genec(Nid::X9_62_PRIME256V1).into(),
        Algorithm::ES256K => genec(Nid::SECP256K1).into(),
        Algorithm::ES384 => genec(Nid::SECP384R1).into(),
        Algorithm::ES512 => genec(Nid::SECP521R1).into(),
        Algorithm::EdDSA => PKey::generate_ed25519().unwrap().into(),
        Algorithm::Ed448 => PKey::generate_ed448().unwrap().into(),
        Algorithm::HS256 => HmacKey::hs256(&[hmac_char; 32]).into(),
        Algorithm::HS384 => HmacKey::hs384(&[hmac_char; 48]).into(),
        Algorithm::HS512 => HmacKey::hs512(&[hmac_char; 64]).into(),
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
            unimplemented!("rust-openssl does not currently support PQ algs")
        }
    }
}

fn map_jswt_alg(alg: Algorithm) -> jsonwebtoken::Algorithm {
    match alg {
        Algorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        Algorithm::RS384 => jsonwebtoken::Algorithm::RS384,
        Algorithm::RS512 => jsonwebtoken::Algorithm::RS512,
        Algorithm::PS256 => jsonwebtoken::Algorithm::PS256,
        Algorithm::PS384 => jsonwebtoken::Algorithm::PS384,
        Algorithm::PS512 => jsonwebtoken::Algorithm::PS512,
        Algorithm::HS256 => jsonwebtoken::Algorithm::HS256,
        Algorithm::HS384 => jsonwebtoken::Algorithm::HS384,
        Algorithm::HS512 => jsonwebtoken::Algorithm::HS512,
        Algorithm::ES256 => jsonwebtoken::Algorithm::ES256,
        Algorithm::ES384 => jsonwebtoken::Algorithm::ES384,
        Algorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        Algorithm::ES256K => unimplemented!("ES256K is unimplemented in jsonwebtoken"),
        Algorithm::ES512 => unimplemented!("ES512 is unimplemented in jsonwebtoken"),
        Algorithm::Ed448 => unimplemented!("Ed448 is unimplemented as EdDSA in jsonwebtoken"),
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
            unimplemented!("post-quantum ML-DSA algs are unimplemented in jsonwebtoken")
        }
    }
}

fn build_validator<K>(key: K) -> ValidationPipeline<Header, Claims, StaticKeyProvider<K>>
where
    K: VerificationKey + Send + Sync + 'static,
{
    ValidationPipeline::<_, _, _>::builder(key.into())
        .with_expiration_validator()
        .with_not_before_validator()
        .with_issued_at_validator()
        .with_type_validator(["JWT", "JOSE"])
        .with_audience_validator("oxitoken")
        .with_issuer_validator("issuer.example.org")
        .with_subscriber_validator(["subscriber@example.org"])
        .with(CustomClaimValidator::new())
        .build()
}

fn jswt_validation(alg: Algorithm) -> jsonwebtoken::Validation {
    let mut jswt_validation = jsonwebtoken::Validation::new(map_jswt_alg(alg));
    jswt_validation.validate_exp = true;
    jswt_validation.validate_nbf = true;
    jswt_validation.validate_aud = true;
    jswt_validation.set_issuer(&["issuer.example.org"]);
    jswt_validation.set_audience(&["oxitoken"]);
    // [`jsonwebtoken`] does not have any means of type ('typ') validation as of 10.1.0
    // [`jsonwebtoken`] does not have any means of subscriber ('sub') validation as of 10.1.0
    // [`jsonwebtoken`] does not have any means of injecting custom validators as of 10.1.0
    jswt_validation
}

fn key_to_jswt(key: &Key) -> jsonwebtoken::DecodingKey {
    match key {
        Key::Hmac(key) => match key.alg() {
            Some(Algorithm::HS256) => jsonwebtoken::DecodingKey::from_secret(&[b'a'; 32]),
            Some(Algorithm::HS384) => jsonwebtoken::DecodingKey::from_secret(&[b'a'; 48]),
            Some(Algorithm::HS512) => jsonwebtoken::DecodingKey::from_secret(&[b'a'; 64]),
            _ => unreachable!("all hmac algs should be covered"),
        },
        Key::PKey(key) => match key.id() {
            Id::RSA | Id::RSA_PSS => {
                jsonwebtoken::DecodingKey::from_rsa_der(key.public_key_to_der().unwrap().as_ref())
            }
            Id::EC => {
                jsonwebtoken::DecodingKey::from_ec_der(key.public_key_to_der().unwrap().as_ref())
            }
            Id::ED25519 => {
                jsonwebtoken::DecodingKey::from_ed_der(key.public_key_to_der().unwrap().as_ref())
            }

            _ => panic!("jsonwebtoken doesn't support this algorithm"),
        },
    }
}

fn encode_validate(alg: Algorithm) {
    let key = genkey(alg, b'a');
    assert_eq!(key.alg().unwrap(), alg);

    // ES256K, ES512, and Ed448 aren't supported by jsonwebtoken as of v10.1.0
    let jswt_pubkey = if matches!(alg, Algorithm::ES512 | Algorithm::ES256K | Algorithm::Ed448) {
        None
    } else {
        Some(key_to_jswt(&key))
    };

    let given_header = header(alg);
    let given_claims = claims();
    let jwt = encode(&key, &given_header, &given_claims).unwrap();

    let validator = build_validator(key);
    let (h, c) = validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    if let Some(jswt_pubkey) = jswt_pubkey {
        let jsonwebtoken::TokenData {
            header: h,
            claims: c,
        } = jsonwebtoken::decode::<Claims>(&jwt, &jswt_pubkey, &jswt_validation(alg)).unwrap();
        assert_eq!(h, given_header.into());
        assert_eq!(c, given_claims);
    }

    let key = genkey(alg, b'b');
    let jwt = encode(&key, &header(alg), &claims()).unwrap();
    let err = validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}

macro_rules! test {
    ($name:ident, $alg:expr) => {
        #[test]
        fn $name() {
            encode_validate($alg);
        }
    };
}

test!(hs256, Algorithm::HS256);
test!(hs384, Algorithm::HS384);
test!(hs512, Algorithm::HS512);
test!(rs256, Algorithm::RS256);
test!(ps256, Algorithm::PS256);
test!(rs384, Algorithm::RS384);
test!(ps384, Algorithm::PS384);
test!(rs512, Algorithm::RS512);
test!(ps512, Algorithm::PS512);
test!(es256, Algorithm::ES256);
test!(es256k, Algorithm::ES256K);
test!(es384, Algorithm::ES384);
test!(es512, Algorithm::ES512);
test!(ed25519, Algorithm::EdDSA);
test!(ed448, Algorithm::Ed448);

#[test]
fn rsa_1024_rejected() {
    let key = Rsa::generate(1024).unwrap();
    let key = PKey::from_rsa(key).unwrap();
    assert_eq!(key.alg(), None);

    let err = encode(&key, &header(Algorithm::RS256), &claims()).unwrap_err();
    assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
}

#[test]
fn unsupported_ec_curve_rejected() {
    let key = EcKey::generate(&EcGroup::from_curve_name(Nid::SECT163R2).unwrap()).unwrap();
    let key = PKey::from_ec_key(key).unwrap();
    assert!(key.alg().is_none());

    let err = encode(&key, &header(Algorithm::RS256), &claims()).unwrap_err();
    assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));
}

#[test]
fn rsa_encode_with_header_key_alg_mismatch_rejected() {
    let key = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(key).unwrap();
    assert_eq!(key.alg().unwrap(), Algorithm::RS256);

    let err = encode(&key, &header(Algorithm::RS384), &claims()).unwrap_err();
    assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
}

#[test]
fn hmac_encode_with_header_key_alg_mismatch_rejected() {
    let key = HmacKey::hs256(&[b'a'; 32]);
    assert_eq!(key.alg().unwrap(), Algorithm::HS256);

    let err = encode(&key, &header(Algorithm::HS384), &claims()).unwrap_err();
    assert!(matches!(err, JwtEncodingError::WrongAlgorithm));
}

#[test]
fn hmac_pkey_rejected() {
    let key = PKey::hmac(&[b'a'; 32]).unwrap();

    // `alg` getter should return `None` since it is unsupported
    assert!((&key).alg().is_none());

    // attempting to sign despite `alg` being `None` should err
    let mut jwt: String = "e30.e30".into();
    let err = (&key).sign_jwt(Algorithm::HS256, &mut jwt).unwrap_err();
    assert!(matches!(err, JwtEncodingError::UnsupportedAlgorithm));

    let err = (&key).verify(jwt.as_bytes(), b"").unwrap_err();
    assert!(matches!(err, JwtError::UnsupportedAlgorithm));
}
