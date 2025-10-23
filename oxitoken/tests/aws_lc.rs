#![allow(clippy::unwrap_used)]
use aws_lc_rs::{
    encoding::AsDer,
    hmac::{
        Algorithm as HmacAlgorithm,
        HMAC_SHA256,
        HMAC_SHA384,
        HMAC_SHA512,
        Key as HmacKey,
    },
    rand::{
        SecureRandom,
        SystemRandom,
    },
    rsa::{
        KeyPair as RsaKeyPair,
        KeySize,
    },
    signature::{
        ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING,
        ECDSA_P256K1_SHA256_FIXED,
        ECDSA_P256K1_SHA256_FIXED_SIGNING,
        ECDSA_P384_SHA384_FIXED,
        ECDSA_P384_SHA384_FIXED_SIGNING,
        ECDSA_P521_SHA512_FIXED,
        ECDSA_P521_SHA512_FIXED_SIGNING,
        ED25519,
        EcdsaKeyPair,
        Ed25519KeyPair,
        KeyPair,
        ParsedPublicKey,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RSA_PSS_2048_8192_SHA256,
        RSA_PSS_2048_8192_SHA384,
        RSA_PSS_2048_8192_SHA512,
        VerificationAlgorithm,
    },
    unstable::signature::{
        ML_DSA_44,
        ML_DSA_44_SIGNING,
        ML_DSA_65,
        ML_DSA_65_SIGNING,
        ML_DSA_87,
        ML_DSA_87_SIGNING,
        PqdsaKeyPair,
    },
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
    crypto::aws_lc::AwsLcVerificationKey,
    encoding::encode,
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

enum KeyType {
    Rsa(RsaKeyPair),
    Ecdsa(EcdsaKeyPair),
    Hmac(WrappedHmacKey),
    Ed25519(Ed25519KeyPair),
    Pqdsa(PqdsaKeyPair),
}

struct WrappedHmacKey {
    key: Box<HmacKey>,
    secret: [u8; 64],
}

fn genhmac(alg: HmacAlgorithm) -> WrappedHmacKey {
    let mut secret = [0; 64];
    SystemRandom::new().fill(&mut secret).unwrap();
    let key = HmacKey::new(alg, &secret);
    WrappedHmacKey {
        key: key.into(),
        secret,
    }
}

fn genkey(alg: Algorithm) -> KeyType {
    match alg {
        Algorithm::RS256 | Algorithm::PS256 => {
            KeyType::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
        }
        Algorithm::RS384 | Algorithm::PS384 => {
            KeyType::Rsa(RsaKeyPair::generate(KeySize::Rsa3072).unwrap())
        }
        Algorithm::RS512 | Algorithm::PS512 => {
            KeyType::Rsa(RsaKeyPair::generate(KeySize::Rsa4096).unwrap())
        }
        Algorithm::ES256K => {
            KeyType::Ecdsa(EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).unwrap())
        }
        Algorithm::ES256 => {
            KeyType::Ecdsa(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
        }
        Algorithm::ES384 => {
            KeyType::Ecdsa(EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap())
        }
        Algorithm::ES512 => {
            KeyType::Ecdsa(EcdsaKeyPair::generate(&ECDSA_P521_SHA512_FIXED_SIGNING).unwrap())
        }
        Algorithm::HS256 => KeyType::Hmac(genhmac(HMAC_SHA256)),
        Algorithm::HS384 => KeyType::Hmac(genhmac(HMAC_SHA384)),
        Algorithm::HS512 => KeyType::Hmac(genhmac(HMAC_SHA512)),
        Algorithm::EdDSA => KeyType::Ed25519(Ed25519KeyPair::generate().unwrap()),
        Algorithm::Ed448 => unimplemented!("Ed448 is unimplemented in aws-lc"),
        Algorithm::MlDsa44 => KeyType::Pqdsa(PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).unwrap()),
        Algorithm::MlDsa65 => KeyType::Pqdsa(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap()),
        Algorithm::MlDsa87 => KeyType::Pqdsa(PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap()),
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

fn make_parsed_pkey(alg: Algorithm, key: &[u8]) -> ParsedPublicKey {
    let kalg: &dyn VerificationAlgorithm = match alg {
        Algorithm::RS256 => &RSA_PKCS1_2048_8192_SHA256,
        Algorithm::RS384 => &RSA_PKCS1_2048_8192_SHA384,
        Algorithm::RS512 => &RSA_PKCS1_2048_8192_SHA512,
        Algorithm::PS256 => &RSA_PSS_2048_8192_SHA256,
        Algorithm::PS384 => &RSA_PSS_2048_8192_SHA384,
        Algorithm::PS512 => &RSA_PSS_2048_8192_SHA512,
        Algorithm::ES256K => &ECDSA_P256K1_SHA256_FIXED,
        Algorithm::ES256 => &ECDSA_P256_SHA256_FIXED,
        Algorithm::ES384 => &ECDSA_P384_SHA384_FIXED,
        Algorithm::ES512 => &ECDSA_P521_SHA512_FIXED,
        Algorithm::EdDSA => &ED25519,
        Algorithm::MlDsa44 => &ML_DSA_44,
        Algorithm::MlDsa65 => &ML_DSA_65,
        Algorithm::MlDsa87 => &ML_DSA_87,
        Algorithm::Ed448 => panic!("Ed448 not supported by aws_lc"),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            panic!("hmac does not use public keys")
        }
    };
    ParsedPublicKey::new(kalg, key).unwrap()
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

fn rsa_encode_validate(alg: Algorithm) {
    let KeyType::Rsa(key) = genkey(alg) else {
        panic!("expected Rsa KeyType")
    };
    let is_pss = matches!(alg, Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512);

    let akey = AwsLcVerificationKey::from_rsa_public_key(key.public_key(), is_pss).unwrap();
    assert_eq!(akey.alg().unwrap(), alg);

    let pkey = make_parsed_pkey(alg, key.public_key().as_ref());
    assert_eq!(pkey.alg().unwrap(), alg);

    let given_header = header(alg);
    let given_claims = claims();
    let jwt = encode(&key, &given_header, &given_claims).unwrap();

    // validate w/ [`AwsLcVerificationKey`]
    let akey_validator = build_validator(akey);
    let (h, c) = akey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // validate w/ a raw [`ParsedPublicKey`]
    let pkey_validator = build_validator(pkey);
    let (h, c) = pkey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // validate w/ `jsonwebtoken` as a sanity check on our JWT encoding/signing
    let jswt_pubkey = jsonwebtoken::DecodingKey::from_rsa_raw_components(
        key.public_key().modulus().big_endian_without_leading_zero(),
        key.public_key()
            .exponent()
            .big_endian_without_leading_zero(),
    );
    let jsonwebtoken::TokenData {
        header: h,
        claims: c,
    } = jsonwebtoken::decode::<Claims>(&jwt, &jswt_pubkey, &jswt_validation(alg)).unwrap();
    assert_eq!(h, given_header.into());
    assert_eq!(c, given_claims);

    // sign a jwt with a new key and assert that its sig is invalid w/ the old keys
    let KeyType::Rsa(key) = genkey(alg) else {
        panic!("expected Rsa KeyType")
    };
    let jwt = encode(&key, &header(alg), &claims()).unwrap();

    let err = akey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);

    let err = pkey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}

fn ed25519_encode_validate(alg: Algorithm) {
    let KeyType::Ed25519(key) = genkey(alg) else {
        panic!("expected Ed25519 KeyType")
    };

    let given_header = header(alg);
    let given_claims = claims();

    // sign/encode
    let jwt = encode(&key, &given_header, &given_claims).unwrap();

    // make pubkeys
    let akey: AwsLcVerificationKey = (&key).into();
    assert_eq!(akey.alg().unwrap(), alg);

    let pkey = make_parsed_pkey(alg, key.public_key().as_ref());
    assert_eq!(pkey.alg().unwrap(), alg);

    // validate/decode w/ [`AwsLcVerificationKey`]
    let akey_validator = build_validator(akey);
    let (h, c) = akey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // validate/decode w/ [`ParsedPublicKey`]
    let pkey_validator = build_validator(pkey);
    let (h, c) = pkey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // decode w/ jsonwebtoken and assert valid w/ same header/claim values
    let jswt_pubkey =
        jsonwebtoken::DecodingKey::from_ed_der(key.public_key().as_der().unwrap().as_ref());
    let jsonwebtoken::TokenData {
        header: h,
        claims: c,
    } = jsonwebtoken::decode::<Claims>(&jwt, &jswt_pubkey, &jswt_validation(alg)).unwrap();
    assert_eq!(h, given_header.into());
    assert_eq!(c, given_claims);

    // encode same data w/ new key and assert invalid signature
    let KeyType::Ed25519(key) = genkey(alg) else {
        panic!("expected Ed25519 KeyType")
    };
    let jwt = encode(&key, &header(alg), &claims()).unwrap();

    let err = akey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);

    let err = pkey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}

fn hmac_encode_validate(alg: Algorithm) {
    let KeyType::Hmac(WrappedHmacKey { key, secret }) = genkey(alg) else {
        panic!("expected Hmac KeyType")
    };
    assert_eq!(key.alg().unwrap(), alg);

    let given_header = header(alg);
    let given_claims = claims();

    // sign/encode
    let jwt = encode(key.as_ref(), &given_header, &given_claims).unwrap();

    // make verification key
    let vkey: AwsLcVerificationKey = key.as_ref().to_owned().try_into().unwrap();
    assert_eq!(vkey.alg().unwrap(), alg);

    // validate/decode w/ [`AwsLcVerificationKey`]
    let vkey_validator = build_validator(vkey);
    let (h, c) = vkey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // validate/decode directly w/ [`HmacKey`]
    let akey_validator = build_validator(*key);
    let (h, c) = akey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // decode w/ jsonwebtoken and assert valid w/ same header/claim values
    let jswt_pubkey = jsonwebtoken::DecodingKey::from_secret(&secret);
    let jsonwebtoken::TokenData {
        header: h,
        claims: c,
    } = jsonwebtoken::decode::<Claims>(&jwt, &jswt_pubkey, &jswt_validation(alg)).unwrap();
    assert_eq!(h, given_header.into());
    assert_eq!(c, given_claims);

    // encode same data w/ new key and assert invalid signature
    let KeyType::Hmac(WrappedHmacKey { key, secret: _ }) = genkey(alg) else {
        panic!("expected Hmac KeyType")
    };
    let jwt = encode(key.as_ref(), &header(alg), &claims()).unwrap();

    let err = vkey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);

    let err = akey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}

fn ecdsa_encode_validate(alg: Algorithm) {
    let KeyType::Ecdsa(key) = genkey(alg) else {
        panic!("expected Ecdsa KeyType")
    };

    let given_header = header(alg);
    let given_claims = claims();
    let mut jwt = encode(&key, &given_header, &given_claims).unwrap();

    let akey: AwsLcVerificationKey = (&key).try_into().unwrap();
    assert_eq!(akey.alg().unwrap(), alg);

    let pkey = make_parsed_pkey(alg, key.public_key().as_ref());
    assert_eq!(pkey.alg().unwrap(), alg);

    // validate w/ [`AwsLcVerificationKey`]
    let akey_validator = build_validator(akey);
    let (header, claims) = akey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(header, given_header);
    assert_eq!(claims, given_claims);

    // validate w/ raw [`ParsedPublicKey`]
    let pkey_validator = build_validator(pkey);
    let (header, claims) = pkey_validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(header, given_header);
    assert_eq!(claims, given_claims);

    // ES512, ES256K, and Ed448 are unimplemented in [`jsonwebtoken`] as of 10.1.0
    if !matches!(alg, Algorithm::ES512 | Algorithm::ES256K | Algorithm::Ed448) {
        let jswt_pubkey =
            jsonwebtoken::DecodingKey::from_ec_der(key.public_key().as_der().unwrap().as_ref());

        let jsonwebtoken::TokenData { header, claims } =
            jsonwebtoken::decode::<Claims>(&jwt, &jswt_pubkey, &jswt_validation(alg)).unwrap();
        assert_eq!(header, given_header.into());
        assert_eq!(claims, given_claims);
    }

    // b64 'QQ' = 'A' = 0x0041
    jwt.push('Q');
    jwt.push('Q');

    let err = akey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);

    let err = pkey_validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}

fn pqdsa_encode_validate(alg: Algorithm) {
    let KeyType::Pqdsa(key) = genkey(alg) else {
        panic!("expected Pqdsa KeyType")
    };

    let given_header = header(alg);
    let given_claims = claims();

    // sign/encode
    let jwt = encode(&key, &given_header, &given_claims).unwrap();

    // make pubkey
    let pubkey: AwsLcVerificationKey = (&key).try_into().unwrap();
    assert_eq!(pubkey.alg().unwrap(), alg);

    // validate/decode
    let validator = build_validator(pubkey);
    let (h, c) = validator.verify(jwt.as_bytes()).unwrap();
    assert_eq!(h, given_header);
    assert_eq!(c, given_claims);

    // encode same data w/ new key and assert invalid signature
    let KeyType::Pqdsa(key) = genkey(alg) else {
        panic!("expected Pqdsa KeyType")
    };
    let jwt = encode(&key, &header(alg), &claims()).unwrap();
    let err = validator.verify(jwt.as_bytes()).unwrap_err();
    assert_eq!(err, JwtError::InvalidSignature);
}
macro_rules! test {
    ($name:ident, $test_fn: ident, $alg:expr) => {
        #[test]
        fn $name() {
            $test_fn($alg);
        }
    };
}

test!(rs256, rsa_encode_validate, Algorithm::RS256);
test!(ps256, rsa_encode_validate, Algorithm::PS256);
test!(rs384, rsa_encode_validate, Algorithm::RS384);
test!(ps384, rsa_encode_validate, Algorithm::PS384);
test!(rs512, rsa_encode_validate, Algorithm::RS512);
test!(ps512, rsa_encode_validate, Algorithm::PS512);
test!(es256, ecdsa_encode_validate, Algorithm::ES256);
test!(es256k, ecdsa_encode_validate, Algorithm::ES256K);
test!(es384, ecdsa_encode_validate, Algorithm::ES384);
test!(es512, ecdsa_encode_validate, Algorithm::ES512);
test!(ed25519, ed25519_encode_validate, Algorithm::EdDSA);
test!(hmac256, hmac_encode_validate, Algorithm::HS256);
test!(hmac384, hmac_encode_validate, Algorithm::HS384);
test!(hmac512, hmac_encode_validate, Algorithm::HS512);
test!(mldsa44, pqdsa_encode_validate, Algorithm::MlDsa44);
test!(mldsa65, pqdsa_encode_validate, Algorithm::MlDsa65);
test!(mldsa87, pqdsa_encode_validate, Algorithm::MlDsa87);
