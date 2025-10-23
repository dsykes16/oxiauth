#![allow(clippy::unwrap_used)]
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{
        KeySize,
        PublicKey as RsaPublicKey,
        PublicKeyComponents,
        RsaParameters,
    },
    signature::{
        ED25519,
        Ed25519KeyPair,
        Ed25519PublicKey,
        KeyPair,
        ParsedPublicKey,
        RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384,
        RSA_PKCS1_2048_8192_SHA512,
        RsaKeyPair,
    },
};
use base64_simd::URL_SAFE_NO_PAD as b64;
use oxitoken::{
    Algorithm,
    claims::Exp,
    crypto::aws_lc::AwsLcVerificationKey,
    encoding::encode,
    error::JwtError,
    header::Alg,
    validation::{
        StaticKeyProvider,
        ValidationPipeline,
        VerificationKey,
    },
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Header {
    alg: Algorithm,
}
impl Alg for Header {
    fn alg(&self) -> Algorithm {
        self.alg
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}
impl Exp for Claims {
    fn exp(&self) -> i64 {
        self.exp
    }
}

#[derive(Debug, Default, serde::Serialize)]
struct Jwk {
    kty: &'static str,
    alg: Algorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
}
impl VerificationKey for Jwk {
    fn alg(&self) -> Option<Algorithm> {
        Some(self.alg)
    }
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        fn rsa_params(alg: Algorithm) -> &'static RsaParameters {
            match alg {
                Algorithm::RS256 => &RSA_PKCS1_2048_8192_SHA256,
                Algorithm::RS384 => &RSA_PKCS1_2048_8192_SHA384,
                Algorithm::RS512 => &RSA_PKCS1_2048_8192_SHA512,
                _ => panic!("rsa_params was called with a non-rsa alg"),
            }
        }
        match self.alg().ok_or(JwtError::UnsupportedAlgorithm)? {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => PublicKeyComponents {
                n: b64.decode_to_vec(self.n.as_ref().unwrap()).unwrap(),
                e: b64.decode_to_vec(self.e.as_ref().unwrap()).unwrap(),
            }
            .verify(rsa_params(self.alg), message, signature)
            .map_err(|_| JwtError::InvalidSignature),
            Algorithm::EdDSA => ParsedPublicKey::new(
                &ED25519,
                b64.decode_to_vec(self.x.as_ref().unwrap()).unwrap(),
            )
            .unwrap()
            .verify_sig(message, signature)
            .map_err(|_| JwtError::InvalidSignature),
            _ => Err(JwtError::UnsupportedAlgorithm),
        }
    }
}

const fn map_rsa_alg(modulus_length: usize) -> Result<Algorithm, JwtError> {
    match modulus_length {
        256 => Ok(Algorithm::RS256),
        384 => Ok(Algorithm::RS384),
        512 => Ok(Algorithm::RS512),
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

impl TryFrom<&RsaPublicKey> for Jwk {
    type Error = JwtError;
    fn try_from(key: &RsaPublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            kty: "RSA",
            alg: map_rsa_alg(key.modulus_len())?,
            n: Some(b64.encode_to_string(key.modulus().big_endian_without_leading_zero())),
            e: Some(b64.encode_to_string(key.exponent().big_endian_without_leading_zero())),
            ..Default::default()
        })
    }
}
impl TryFrom<&Ed25519PublicKey> for Jwk {
    type Error = JwtError;
    fn try_from(key: &Ed25519PublicKey) -> Result<Self, Self::Error> {
        Ok(Self {
            kty: "OKP",
            crv: Some("Ed25519"),
            alg: Algorithm::EdDSA,
            x: Some(b64.encode_to_string(key.as_ref())),
            ..Default::default()
        })
    }
}

fn main() {
    // make and sign a jwt/jwk pair (RS512)
    let key = RsaKeyPair::generate(KeySize::Rsa4096).unwrap();
    let sub = "test".into();
    let exp: i64 = 1_865_013_100;
    let header = Header {
        alg: map_rsa_alg(key.public_modulus_len()).unwrap(),
    };
    let claims = Claims { sub, exp };
    let jwt = encode(&key, &header, &claims).unwrap();
    let jwk: Jwk = key.public_key().try_into().unwrap();
    let json_jwk = serde_json::to_string(&jwk).unwrap();
    let pubkey = b64.encode_to_string(key.public_key().as_der().unwrap().as_ref());

    println!("JWT: {jwt}");
    println!("JWK: {json_jwk}");
    println!("PubKey Base64 DER: {pubkey}");

    // [`ValidationPipeline::builder`] can accept our [`Jwk`] directly since we implemented [`VerificationKey`] for it
    let validator = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(jwk.into())
        .with_expiration_validator()
        .build();

    // verify/decode the JWT
    validator.verify(jwt.as_bytes()).unwrap();

    // decode and validate by parsing the DER public key
    let decoding_key: AwsLcVerificationKey = ParsedPublicKey::new(
        &RSA_PKCS1_2048_8192_SHA512,
        key.public_key().as_der().unwrap().as_ref(),
    )
    .unwrap()
    .try_into()
    .unwrap();

    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(decoding_key.into())
            .with_expiration_validator()
            .build();

    // verify/decode the JWT
    validator.verify(jwt.as_bytes()).unwrap();

    // ED25519 encoding
    let ekp = Ed25519KeyPair::generate().unwrap();
    let header = Header {
        alg: Algorithm::EdDSA,
    };
    let jwt = encode(&ekp, &header, &claims).unwrap();
    let jwk = Jwk::try_from(ekp.public_key()).unwrap();
    println!("EdJWK: {}", &jwt);
    println!("EdJWK: {}", serde_json::to_string(&jwk).unwrap());

    let validator = ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(jwk.into())
        .with_expiration_validator()
        .build();

    // verify/decode the JWT
    validator.verify(jwt.as_bytes()).unwrap();
}
