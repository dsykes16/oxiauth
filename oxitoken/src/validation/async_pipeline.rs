use futures::{
    Future,
    TryFutureExt,
};
use serde::Deserialize;
use std::{
    borrow::Borrow,
    hash::Hash,
    pin::Pin,
};

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
    errors::JwtError,
    header::{
        Alg,
        Typ,
    },
    validation::{
        VerificationKey,
        validators::{
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

pub trait AsyncTokenValidator<H: ?Sized, C: ?Sized> {
    fn validate<'a>(
        &self,
        header: &H,
        claims: &C,
    ) -> Pin<Box<dyn Future<Output = Result<(), JwtError>> + Send + 'a>>;
}

pub trait AsyncKeyProvider<H: ?Sized, C: ?Sized> {
    type Key: VerificationKey;
    async fn resolve_key<'a, 'b>(
        &self,
        header: &'b H,
        claims: &'b C,
    ) -> Result<&'a Self::Key, JwtError>
    where
        Self: 'a,
        Self::Key: 'a;
}

pub struct AsyncValidationPipelineBuilder<H, C, KP>
where
    KP: AsyncKeyProvider<H, C>,
{
    validators: Vec<Box<dyn TokenValidator<H, C>>>,
    async_validators: Vec<Box<dyn AsyncTokenValidator<H, C>>>,
    key_provider: KP,
}
impl<H, C, KP> AsyncValidationPipelineBuilder<H, C, KP>
where
    for<'de> H: Deserialize<'de> + Alg,
    for<'de> C: Deserialize<'de>,
    KP: AsyncKeyProvider<H, C> + 'static,
{
    pub(crate) fn new(key_provider: KP) -> Self {
        Self {
            async_validators: Vec::new(),
            validators: Vec::new(),
            key_provider: key_provider,
        }
    }

    pub fn with_issuer_validator(mut self, iss: impl Into<String>) -> Self
    where
        C: Iss,
    {
        self.validators
            .push(Box::new(IssuerValidator::new(iss.into())));
        self
    }

    pub fn with_audience_validator(mut self, aud: impl Into<String>) -> Self
    where
        C: Aud,
    {
        self.validators
            .push(Box::new(AudienceValidator::new(aud.into())));
        self
    }

    pub fn with_not_before_validator(mut self) -> Self
    where
        C: Nbf,
    {
        self.validators.push(Box::new(NotBeforeValidator::new()));
        self
    }

    pub fn with_expiration_validator(mut self) -> Self
    where
        C: Exp,
    {
        self.validators.push(Box::new(ExpirationValidator::new()));
        self
    }

    pub fn with_issued_at_validator(mut self) -> Self
    where
        C: Iat,
    {
        self.validators.push(Box::new(IssuedAtValidator::new()));
        self
    }

    pub fn with_type_validator<T>(mut self, accepted_types: impl IntoIterator<Item = T>) -> Self
    where
        H: Typ,
        T: Hash + Eq + 'static + Borrow<H::Type>,
        H::Type: Hash + PartialEq<T> + Eq,
    {
        self.validators
            .push(Box::new(TypeValidator::new(accepted_types.into_iter())));
        self
    }

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

    pub fn with(mut self, validator: impl TokenValidator<H, C> + 'static) -> Self {
        self.validators.push(Box::new(validator));
        self
    }

    pub fn with_async(mut self, async_validator: impl AsyncTokenValidator<H, C> + 'static) -> Self {
        self.async_validators.push(Box::new(async_validator));
        self
    }

    pub fn build(self) -> AsyncValidationPipeline<H, C, KP> {
        AsyncValidationPipeline::new(self.async_validators, self.validators, self.key_provider)
    }
}

pub struct AsyncValidationPipeline<H, C, KP> {
    async_validators: Vec<Box<dyn AsyncTokenValidator<H, C>>>,
    validators: Vec<Box<dyn TokenValidator<H, C>>>,
    key_provider: KP,
}

impl<H, C, KP> AsyncValidationPipeline<H, C, KP>
where
    for<'de> H: Deserialize<'de> + Alg,
    for<'de> C: Deserialize<'de>,
    KP: AsyncKeyProvider<H, C> + 'static,
{
    pub fn builder(key_provider: KP) -> AsyncValidationPipelineBuilder<H, C, KP> {
        AsyncValidationPipelineBuilder::new(key_provider)
    }

    pub(crate) fn new(
        async_validators: Vec<Box<dyn AsyncTokenValidator<H, C>>>,
        validators: Vec<Box<dyn TokenValidator<H, C>>>,
        key_provider: KP,
    ) -> Self {
        Self {
            async_validators,
            validators,
            key_provider,
        }
    }

    pub async fn verify(&self, token: &[u8]) -> Result<(H, C), JwtError> {
        let split = SplitJwt::try_from(token)?;
        let decoded = DecodedJwt::try_from(&split)?;

        let header = serde_json::from_slice::<H>(decoded.decoded_header())
            .map_err(|_| JwtError::HeaderDeserialization)?;
        let claims = serde_json::from_slice::<C>(decoded.decoded_claims())
            .map_err(|_| JwtError::ClaimsDeserialization)?;

        let header_alg = header.alg();
        futures::future::try_join3(
            self.key_provider
                .resolve_key(&header, &claims)
                .and_then(|key| async move {
                    if header_alg != key.alg() {
                        Err(JwtError::WrongAlgorithm)
                    } else {
                        Ok(key)
                    }
                })
                .and_then(|key| {
                    self.verify_signature(split.b64_message(), decoded.decoded_signature(), key)
                }),
            self.run_validators(&header, &claims),
            futures::future::try_join_all(
                self.async_validators
                    .iter()
                    .map(|f| f.validate(&header, &claims)),
            ),
        )
        .await?;

        Ok((header, claims))
    }

    async fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        key: &KP::Key,
    ) -> Result<(), JwtError> {
        key.verify(&message, &signature)?;
        Ok(())
    }

    async fn run_validators(&self, header: &H, claims: &C) -> Result<(), JwtError> {
        for v in &self.validators {
            v.validate(header, claims)?
        }
        Ok(())
    }
}
