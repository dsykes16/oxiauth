use std::{
    borrow::Borrow,
    hash::Hash,
};

use serde::Deserialize;

use crate::{
    claims::{
        Aud,
        Exp,
        Iat,
        Iss,
        Nbf,
        Sub,
    },
    decoding::{
        DecodedJwt,
        SplitJwt,
    },
    error::JwtError,
    header::{
        Alg,
        Typ,
    },
    validation::{
        KeyProvider,
        VerificationKey,
        validator::{
            AudienceValidator,
            ExpirationValidator,
            IssuedAtValidator,
            IssuerValidator,
            NotBeforeValidator,
            SubscriberValidator,
            TokenValidator,
            TypeValidator,
        },
    },
};

pub struct ValidationPipelineBuilder<H, C, KP>
where
    KP: KeyProvider<H, C>,
{
    validators: Vec<Box<dyn TokenValidator<H, C> + Send + Sync>>,
    key_provider: KP,
    size_limit: Option<usize>,
}
impl<H, C, KP> ValidationPipelineBuilder<H, C, KP>
where
    for<'de> H: Deserialize<'de> + Alg,
    for<'de> C: Deserialize<'de>,
    KP: KeyProvider<H, C> + Send + Sync + 'static,
{
    pub(crate) fn new(key_provider: KP) -> Self {
        Self {
            validators: Vec::new(),
            key_provider,
            size_limit: None,
        }
    }

    /// Caps accepted JWT size to `size_limit` bytes
    ///
    /// JWTs above this size will return a [`JwtError::OverSizeLimit`]
    pub const fn with_max_size(mut self, size_limit: usize) -> Self {
        self.size_limit = Some(size_limit);
        self
    }

    /// Rejects JWTs where the `iss` field does not match the given `iss` value.
    pub fn with_issuer_validator(mut self, iss: impl Into<String>) -> Self
    where
        C: Iss,
    {
        self.validators
            .push(Box::new(IssuerValidator::new(iss.into())));
        self
    }

    /// Rejects JWTs that do not contain the given `aud` value in their `aud` list.
    pub fn with_audience_validator(mut self, aud: impl Into<String>) -> Self
    where
        C: Aud,
    {
        self.validators
            .push(Box::new(AudienceValidator::new(aud.into())));
        self
    }

    /// Rejects JWTs with an `nbf` time greater than the current system time.
    pub fn with_not_before_validator(mut self) -> Self
    where
        C: Nbf,
    {
        self.validators.push(Box::new(NotBeforeValidator::new()));
        self
    }

    /// Rejects JWTs with an `exp` time less than the current system time.
    pub fn with_expiration_validator(mut self) -> Self
    where
        C: Exp,
    {
        self.validators.push(Box::new(ExpirationValidator::new()));
        self
    }

    /// Rejects JWTs with an `iat` time greater than the current system time.
    ///
    /// # Note
    /// This is a reference implementation to demonstrate usage of the [`Iat`] trait
    /// A more realistic usage of the `iat` field is in combination with the `jti` field
    /// to assist with cache management (i.e. if `iat` time is less then most recent
    /// `jti` revocation cache update; token can be immediately processed).
    pub fn with_issued_at_validator(mut self) -> Self
    where
        C: Iat,
    {
        self.validators.push(Box::new(IssuedAtValidator::new()));
        self
    }

    /// Rejects JWTs with a `typ` not in the `accepted_types` list
    pub fn with_type_validator<T>(mut self, accepted_types: impl IntoIterator<Item = T>) -> Self
    where
        H: Typ,
        T: Hash + Eq + Borrow<H::Type> + Send + Sync + 'static,
        H::Type: Hash + Eq,
    {
        self.validators
            .push(Box::new(TypeValidator::new(accepted_types)));
        self
    }

    /// Rejects JWTs with a `sub` not in the `accepted_subscribers` list
    pub fn with_subscriber_validator(
        mut self,
        accepted_subscribers: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self
    where
        C: Sub,
    {
        self.validators.push(Box::new(SubscriberValidator::new(
            accepted_subscribers.into_iter(),
        )));
        self
    }

    /// Adds a custom validator to the validation pipeline.
    /// This method may be chained to add multiple custom validators.
    pub fn with(mut self, validator: impl TokenValidator<H, C> + Send + Sync + 'static) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    /// Finalizes the validation pipeline construction.
    pub fn build(self) -> ValidationPipeline<H, C, KP> {
        ValidationPipeline::new(self.validators, self.key_provider, self.size_limit)
    }
}

/// Validation pipeline that, once built, can decode and validate compact-encoded JWTs
pub struct ValidationPipeline<H, C, KP> {
    validators: Vec<Box<dyn TokenValidator<H, C> + Send + Sync>>,
    key_provider: KP,
    size_limit: Option<usize>,
}

impl<H, C, KP> ValidationPipeline<H, C, KP>
where
    for<'de> H: Deserialize<'de> + Alg,
    for<'de> C: Deserialize<'de>,
    KP: KeyProvider<H, C> + Send + Sync + 'static,
{
    // Returns a new [`ValidationPipelineBuilder`].
    pub fn builder(key_provider: KP) -> ValidationPipelineBuilder<H, C, KP> {
        ValidationPipelineBuilder::new(key_provider)
    }

    pub(crate) fn new(
        validators: Vec<Box<dyn TokenValidator<H, C> + Send + Sync>>,
        key_provider: KP,
        size_limit: Option<usize>,
    ) -> Self {
        Self {
            validators,
            key_provider,
            size_limit,
        }
    }

    /// Verifies a JWT using the validation pipeline's key provider and validators.
    ///
    /// # Errors
    ///
    /// - [`JwtError::OverSizeThreshold`] when a `size_limit` has been specified
    ///   and the raw JWT size, in bytes, is greater than that limit.
    /// - [`JwtError::InvalidSectionCount`] when the number of dot-delimited
    ///   sections in the JWT does not match the expected count
    /// - [`JwtError::InvalidEncoding`] when any section of the JWT is not
    ///   valid base-64 URL-safe encoded.
    /// - [`JwtError::HeaderDeserialization`] when the header cannot be
    ///   deserialized from JSON into the specified header struct (i.e. `H` generic)
    /// - [`JwtError::ClaimsDeserialization`] when the claims cannot be
    ///   deserialized from JSON into the specified claims struct (i.e. `C` generic)
    /// - [`JwtError::VerificationKeyNotFound`] when the [`KeyProvider`] cannot
    ///   resolve a key to be used for cryptographic operations.
    /// - [`JwtError::UnsupportedAlgorithm`] when the [`VerificationKey`] algorithm
    ///   is unsupported
    /// - [`JwtError::WrongAlgorithm`] when the header `alg` field does not match
    ///   the [`VerificationKey`] algorithm
    /// - [`JwtError::InvalidSignature`] when the JWT signature is invalid per
    ///   the [`VerificationKey`]
    /// - Any other [`JwtError`] raised by a [`TokenValidator`] which is included
    ///   in the validation pipeline
    pub fn verify(&self, token: &[u8]) -> Result<(H, C), JwtError> {
        if let Some(size_limit) = self.size_limit
            && token.len() > size_limit
        {
            return Err(JwtError::OverSizeThreshold);
        }
        let split = SplitJwt::try_from(token)?;
        let decoded = DecodedJwt::try_from(&split)?;

        let header = serde_json::from_slice::<H>(decoded.decoded_header())
            .map_err(|_| JwtError::HeaderDeserialization)?;
        let claims = serde_json::from_slice::<C>(decoded.decoded_claims())
            .map_err(|_| JwtError::ClaimsDeserialization)?;

        // try to get a matching key from the resolver
        let key = self.key_provider.resolve_key(&header, &claims)?;

        // alg validation is non-negotiable per RFC-7519
        if header.alg() != key.alg().ok_or(JwtError::UnsupportedAlgorithm)? {
            return Err(JwtError::WrongAlgorithm);
        }

        // validate signature
        key.verify(split.b64_message(), decoded.decoded_signature())?;

        // run field validators
        self.run_validators(&header, &claims)?;

        Ok((header, claims))
    }

    fn run_validators(&self, header: &H, claims: &C) -> Result<(), JwtError> {
        for v in &self.validators {
            v.validate(header, claims)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use serde::Deserialize;
    use serde_with::{
        OneOrMany,
        formats::PreferMany,
        serde_as,
    };

    use crate::{
        Algorithm,
        JwtError,
        claims::{
            Aud,
            Exp,
            Iat,
            Iss,
            Jti,
            Nbf,
            Sub,
        },
        header::{
            Alg,
            Typ,
        },
        validation::{
            KeyProvider,
            StaticKeyProvider,
            ValidationPipeline,
            VerificationKey,
            pipeline::ValidationPipelineBuilder,
            validator::TokenValidator,
        },
    };
    static EMPTY_STRING_ARRAY: [String; 0] = [];

    struct MockVerificationKey;
    impl MockVerificationKey {
        fn new() -> Self {
            Self {}
        }
    }
    impl VerificationKey for MockVerificationKey {
        fn alg(&self) -> Option<Algorithm> {
            Some(Algorithm::HS256)
        }
        fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<(), crate::JwtError> {
            Ok(())
        }
    }

    #[derive(Debug, serde::Deserialize)]
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

    #[serde_as]
    #[derive(Debug, Deserialize)]
    struct Claims {
        iss: Option<String>,
        sub: Option<String>,
        #[serde_as(as = "Option<OneOrMany<_, PreferMany>>")]
        aud: Option<Vec<String>>,
        exp: Option<i64>,
        nbf: Option<i64>,
        iat: Option<i64>,
        jti: Option<String>,
    }
    impl Iss for Claims {
        fn iss(&self) -> &str {
            match &self.iss {
                Some(iss) => iss,
                None => "",
            }
        }
    }
    impl Sub for Claims {
        fn sub(&self) -> &str {
            match &self.sub {
                Some(sub) => sub,
                None => "",
            }
        }
    }
    impl Aud for Claims {
        fn aud(&self) -> impl Iterator<Item = impl AsRef<str>> {
            self.aud
                .as_ref()
                .map_or_else(|| EMPTY_STRING_ARRAY.iter(), |aud| aud.iter())
        }
    }
    impl Exp for Claims {
        fn exp(&self) -> i64 {
            self.exp.unwrap_or(0)
        }
    }
    impl Nbf for Claims {
        fn nbf(&self) -> i64 {
            self.nbf.unwrap_or(i64::MAX)
        }
    }
    impl Iat for Claims {
        fn iat(&self) -> i64 {
            self.iat.unwrap_or(i64::MAX)
        }
    }
    impl Jti for Claims {
        fn jti(&self) -> &str {
            match &self.jti {
                Some(jti) => jti,
                None => "",
            }
        }
    }

    fn base_validator_builder()
    -> ValidationPipelineBuilder<Header, Claims, StaticKeyProvider<MockVerificationKey>> {
        ValidationPipelineBuilder::new(StaticKeyProvider::new(MockVerificationKey::new()))
    }

    #[test]
    fn type_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.e30.";
        let expected_types = ["TEST-JWT", "TEST"];
        let validator = base_validator_builder()
            .with_type_validator(expected_types)
            .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"JWT"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::WrongType);
    }

    #[test]
    fn issuer_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"iss":"test-issuer"}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.";
        let expected_issuer = "test-issuer";
        let validator = base_validator_builder()
            .with_issuer_validator(expected_issuer)
            .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"iss":"bad-test-issuer"}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJpc3MiOiJiYWQtdGVzdC1pc3N1ZXIifQ.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::WrongIssuer);
    }

    #[test]
    fn subscriber_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"sub":"test-subscriber"}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJzdWIiOiJ0ZXN0LXN1YnNjcmliZXIifQ.";
        let expected_subscriber = "test-subscriber";

        let validator = base_validator_builder()
            .with_subscriber_validator(vec![expected_subscriber])
            .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"sub":"bad-test-subscriber"}
        let token =
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJzdWIiOiJiYWQtdGVzdC1zdWJzY3JpYmVyIn0.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::WrongSubscriber);
    }

    #[test]
    fn audience_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"aud":"test-audience"}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.";
        let expected_audience = "test-audience";

        let validator = base_validator_builder()
            .with_audience_validator(expected_audience)
            .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"aud":"bad-test-audience"}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJhdWQiOiJiYWQtdGVzdC1hdWRpZW5jZSJ9.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::WrongAudience);
    }

    #[test]
    fn not_before_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"nbf": 1760644834}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJuYmYiOiAxNzYwNjQ0ODM0fQ.";

        let validator = base_validator_builder().with_not_before_validator().build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"nbf": 1865131776}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJuYmYiOiAxODY1MTMxNzc2fQ.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::NotValidYet);
    }

    #[test]
    fn issued_at_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"iat": 1760644834}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJpYXQiOiAxNzYwNjQ0ODM0fQ.";

        let validator = base_validator_builder().with_issued_at_validator().build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"iat": 1865131776}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJpYXQiOiAxODY1MTMxNzc2fQ.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::IssuedInFuture);
    }

    #[test]
    fn expiration_validator() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"exp": 1865131776}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJleHAiOiAxODY1MTMxNzc2fQ.";

        let validator = base_validator_builder().with_expiration_validator().build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {"exp": 1760644834}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.eyJleHAiOiAxNzYwNjQ0ODM0fQ.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::Expired);
    }

    #[test]
    fn custom_validator() {
        trait Foo {
            fn foo(&self) -> &str;
        }
        #[derive(Debug, Deserialize)]
        struct CustomHeader {
            alg: Algorithm,
            foo: String,
        }
        impl Alg for CustomHeader {
            fn alg(&self) -> Algorithm {
                self.alg
            }
        }
        impl Foo for CustomHeader {
            fn foo(&self) -> &str {
                &self.foo
            }
        }
        struct CustomValidator;
        impl CustomValidator {
            fn new() -> Self {
                Self {}
            }
        }
        impl<H, C> TokenValidator<H, C> for CustomValidator
        where
            H: Foo,
        {
            fn validate(&self, header: &H, _: &C) -> Result<(), JwtError> {
                if header.foo() == "bar" {
                    Ok(())
                } else {
                    Err(JwtError::CustomValidationError("foo is not bar"))
                }
            }
        }

        // header: {"alg":"HS256","foo":"bar"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsImZvbyI6ImJhciJ9.e30.";

        let validator = ValidationPipeline::<CustomHeader, Claims, _>::builder(
            StaticKeyProvider::new(MockVerificationKey::new()),
        )
        .with(CustomValidator::new())
        .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","foo":"baz"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsImZvbyI6ImJheiJ9.e30.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::CustomValidationError("foo is not bar"));
    }

    #[test]
    fn invalid_signature_encoding() {
        #[derive(Debug, serde::Deserialize)]
        struct Empty;
        impl Alg for Empty {
            fn alg(&self) -> Algorithm {
                Algorithm::HS256
            }
        }

        let token = b"e30.e30.-=-";
        let err = ValidationPipeline::<Empty, Empty, _>::builder(StaticKeyProvider::new(
            MockVerificationKey::new(),
        ))
        .build()
        .verify(token)
        .unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);
    }

    #[test]
    fn type_as_enum() {
        #[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
        #[allow(clippy::upper_case_acronyms)]
        enum ContentType {
            JWT,
            JOSE,
            TEST,
        }
        #[derive(Debug, serde::Deserialize)]
        struct H {
            alg: Algorithm,
            typ: ContentType,
        }
        impl Alg for H {
            fn alg(&self) -> Algorithm {
                self.alg
            }
        }

        impl Typ for H {
            type Type = ContentType;
            fn typ(&self) -> &Self::Type {
                &self.typ
            }
        }

        // header: {"alg":"HS256","typ":"JWT"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.";
        let expected_types = [ContentType::JWT, ContentType::JOSE];
        let validator: ValidationPipeline<H, Claims, StaticKeyProvider<MockVerificationKey>> =
            ValidationPipelineBuilder::new(StaticKeyProvider::new(MockVerificationKey::new()))
                .with_type_validator(expected_types)
                .build();
        validator.verify(token).unwrap();

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.e30.";
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::WrongType);
    }

    #[test]
    fn unresolvable_key_returns_err() {
        struct MockKeystore;
        impl KeyProvider<Header, Claims> for MockKeystore {
            type Key = MockVerificationKey;
            fn resolve_key(&self, _: &Header, _: &Claims) -> Result<&Self::Key, JwtError> {
                Err(JwtError::VerificationKeyNotFound)
            }
        }

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.e30.";
        let validator =
            ValidationPipelineBuilder::<Header, Claims, MockKeystore>::new(MockKeystore {}).build();
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::VerificationKeyNotFound);
    }

    #[test]
    fn key_without_alg_returns_err() {
        struct BadKey;
        impl VerificationKey for BadKey {
            fn alg(&self) -> Option<Algorithm> {
                None
            }
            fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> {
                unreachable!(
                    "verification should not be attempted if key algorithm cannot be resolved to RFC-defined JWT algorithm"
                );
            }
        }

        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {}
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.e30.";
        let key = BadKey {};
        let validator =
            ValidationPipelineBuilder::<Header, Claims, StaticKeyProvider<_>>::new(key.into())
                .build();
        let err = validator.verify(token).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn input_above_size_limit_returns_err() {
        // header: {"alg":"HS256","typ":"TEST"}
        // claims: {}
        let good_jwt = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IlRFU1QifQ.e30.";
        let bad_jwt = [b'a'; 101];

        let validator = base_validator_builder().with_max_size(100).build();

        validator.verify(good_jwt).unwrap();
        let err = validator.verify(&bad_jwt).unwrap_err();
        assert_eq!(err, JwtError::OverSizeThreshold);
    }
}
