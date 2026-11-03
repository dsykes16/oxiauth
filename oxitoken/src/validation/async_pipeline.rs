use std::future::{
    Future,
    ready,
};

use futures::future::{
    BoxFuture,
    try_join_all,
};
use serde::Deserialize;

use crate::{
    error::JwtError,
    header::{
        Alg,
        Kid,
    },
    validation::{
        KeyProvider,
        StaticKeyProvider,
        VerificationKey,
        keystore::LocalKeystore,
        pipeline::{
            PipelineCore,
            ValidationPipelineBuilder,
        },
    },
};

/// Async counterpart of [`KeyProvider`], for keys that may need I/O to resolve
/// (e.g. a JWKS endpoint, a Cloud KMS or an HSM).
///
/// [`StaticKeyProvider`] and [`LocalKeystore`] implement both traits, so they can
/// be used with either pipeline.
///
/// # Example Implementation
///
/// A provider backed by a shared cache can hand out [`Arc`](std::sync::Arc)-wrapped
/// keys, since [`VerificationKey`] is implemented for `Arc<K>` and `&K`:
///
/// ```rust
/// use std::{collections::HashMap, sync::{Arc, RwLock}};
/// use oxitoken::{
///     error::JwtError,
///     header::Kid,
///     validation::{AsyncKeyProvider, VerificationKey},
/// };
///
/// pub struct CachedJwks<K> {
///     keys: RwLock<HashMap<String, Arc<K>>>,
/// }
///
/// impl<H, C, K> AsyncKeyProvider<H, C> for CachedJwks<K>
/// where
///     H: Kid + Sync,
///     C: Sync,
///     K: VerificationKey + Send + Sync,
/// {
///     type Key<'a> = Arc<K> where Self: 'a, H: 'a, C: 'a;
///
///     async fn resolve_key<'a>(&'a self, header: &'a H, _: &'a C) -> Result<Arc<K>, JwtError> {
///         let cached = self.keys.read().ok().and_then(|keys| keys.get(header.kid()).cloned());
///         // on a cache miss, a real implementation would refresh from the JWKS endpoint here
///         cached.ok_or(JwtError::VerificationKeyNotFound)
///     }
/// }
/// ```
pub trait AsyncKeyProvider<H: ?Sized, C: ?Sized> {
    /// Type of [`VerificationKey`] provided; may borrow from the provider
    /// (e.g. `&'a K`) or be owned (e.g. `Arc<K>`).
    type Key<'a>: VerificationKey
    where
        Self: 'a,
        H: 'a,
        C: 'a;

    /// Attempt to resolve the key to be used for JWT signature verification.
    ///
    /// Implementations may be written as `async fn`.
    ///
    /// # Errors
    ///
    /// - [`JwtError::VerificationKeyNotFound`] when the appropriate key is not available
    ///   to the [`AsyncKeyProvider`].
    fn resolve_key<'a>(
        &'a self,
        header: &'a H,
        claims: &'a C,
    ) -> impl Future<Output = Result<Self::Key<'a>, JwtError>> + Send;
}

impl<H, C, VK> AsyncKeyProvider<H, C> for StaticKeyProvider<VK>
where
    VK: VerificationKey + Sync,
{
    type Key<'a>
        = &'a VK
    where
        Self: 'a,
        H: 'a,
        C: 'a;

    fn resolve_key<'a>(
        &'a self,
        header: &'a H,
        claims: &'a C,
    ) -> impl Future<Output = Result<&'a VK, JwtError>> + Send {
        ready(KeyProvider::resolve_key(self, header, claims))
    }
}

impl<H, C, VK> AsyncKeyProvider<H, C> for LocalKeystore<VK>
where
    H: Kid,
    VK: VerificationKey + Sync,
{
    type Key<'a>
        = &'a VK
    where
        Self: 'a,
        H: 'a,
        C: 'a;

    fn resolve_key<'a>(
        &'a self,
        header: &'a H,
        claims: &'a C,
    ) -> impl Future<Output = Result<&'a VK, JwtError>> + Send {
        ready(KeyProvider::resolve_key(self, header, claims))
    }
}

/// Trait for implementing custom async token validator layers (e.g. a revocation
/// lookup against a database).
///
/// Async validators run only after the signature has been verified and every
/// [`TokenValidator`](crate::validation::TokenValidator) has passed, so they never
/// see forged or otherwise invalid tokens. All async validators in a pipeline run
/// concurrently.
///
/// Implementations may be written as `async fn`; see [`AsyncValidationPipeline`]
/// for an example.
pub trait AsyncTokenValidator<H: ?Sized, C: ?Sized> {
    /// Given the `header` and `claims` for a JWT, perform some validation step.
    ///
    /// # Errors
    ///
    /// This method MUST return a [`JwtError`] if the JWT `header` and/or `claims`
    /// do not pass the validation step performed by this [`AsyncTokenValidator`].
    fn validate(&self, header: &H, claims: &C)
    -> impl Future<Output = Result<(), JwtError>> + Send;
}

/// Dyn-compatible form of [`AsyncTokenValidator`], so validators can be boxed.
trait DynAsyncTokenValidator<H: ?Sized, C: ?Sized>: Send + Sync {
    fn validate_boxed<'a>(
        &'a self,
        header: &'a H,
        claims: &'a C,
    ) -> BoxFuture<'a, Result<(), JwtError>>;
}

impl<H, C, V> DynAsyncTokenValidator<H, C> for V
where
    H: ?Sized,
    C: ?Sized,
    V: AsyncTokenValidator<H, C> + Send + Sync,
{
    fn validate_boxed<'a>(
        &'a self,
        header: &'a H,
        claims: &'a C,
    ) -> BoxFuture<'a, Result<(), JwtError>> {
        Box::pin(self.validate(header, claims))
    }
}

/// Async validators held by an [`AsyncValidationPipeline`] and its builder.
pub struct AsyncValidators<H, C>(Vec<Box<dyn DynAsyncTokenValidator<H, C>>>);

impl<H, C, KP> ValidationPipelineBuilder<H, C, KP, AsyncValidators<H, C>>
where
    for<'de> H: Deserialize<'de> + Alg + Send + Sync,
    for<'de> C: Deserialize<'de> + Send + Sync,
    KP: AsyncKeyProvider<H, C> + Send + Sync,
{
    /// Adds a custom async validator to the validation pipeline.
    /// This method may be chained to add multiple custom async validators.
    pub fn with_async(
        mut self,
        validator: impl AsyncTokenValidator<H, C> + Send + Sync + 'static,
    ) -> Self {
        self.async_validators.0.push(Box::new(validator));
        self
    }

    /// Finalizes the validation pipeline construction.
    pub fn build(self) -> AsyncValidationPipeline<H, C, KP> {
        AsyncValidationPipeline {
            core: self.core,
            key_provider: self.key_provider,
            async_validators: self.async_validators,
        }
    }
}

/// Async validation pipeline that, once built, can decode and validate compact-encoded JWTs
/// using an [`AsyncKeyProvider`] and [`AsyncTokenValidator`]s.
///
/// The returned future is [`Send`], so it can be used with multi-threaded runtimes.
///
/// # Example
///
/// ```rust
/// use oxitoken::{
///     claims::Jti,
///     error::JwtError,
///     validation::{AsyncTokenValidator, AsyncValidationPipeline, StaticKeyProvider},
///#    Algorithm,
///#    header::Alg,
///#    validation::VerificationKey,
/// };
///
/// pub struct RevocationValidator;
/// impl<H: Sync, C: Jti + Sync> AsyncTokenValidator<H, C> for RevocationValidator {
///     async fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
///         // a real implementation would look `claims.jti()` up in a revocation store
///         if claims.jti() == "revoked" {
///             Err(JwtError::CustomValidationError("token revoked"))
///         } else {
///             Ok(())
///         }
///     }
/// }
///
///# #[derive(serde::Deserialize)]
///# struct Header { alg: Algorithm }
///# impl Alg for Header { fn alg(&self) -> Algorithm { self.alg } }
///# #[derive(serde::Deserialize)]
///# struct Claims { jti: String }
///# impl Jti for Claims { fn jti(&self) -> &str { &self.jti } }
///# struct MockVerificationKey;
///# impl VerificationKey for MockVerificationKey {
///#     fn alg(&self) -> Option<Algorithm> { Some(Algorithm::HS256) }
///#     fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> { Ok(()) }
///# }
///# fn some_key_provider() -> StaticKeyProvider<MockVerificationKey> {
///#     MockVerificationKey.into()
///# }
///# // header: {"alg":"HS256"}
///# // claims: {"jti":"abc"}
///# let token = b"eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJhYmMifQ.";
/// let pipeline = AsyncValidationPipeline::<Header, Claims, _>::builder(some_key_provider())
///     .with_max_size(8 * 1024)
///     .with_async(RevocationValidator)
///     .build();
///
/// // any executor works; `block_on` keeps this example runtime-agnostic
/// let (_header, claims) = futures::executor::block_on(pipeline.verify(token))?;
///# assert_eq!(claims.jti(), "abc");
///# Ok::<(), JwtError>(())
/// ```
pub struct AsyncValidationPipeline<H, C, KP> {
    core: PipelineCore<H, C>,
    key_provider: KP,
    async_validators: AsyncValidators<H, C>,
}

impl<H, C, KP> AsyncValidationPipeline<H, C, KP>
where
    for<'de> H: Deserialize<'de> + Alg + Send + Sync,
    for<'de> C: Deserialize<'de> + Send + Sync,
    KP: AsyncKeyProvider<H, C> + Send + Sync,
{
    /// Returns a new builder for an [`AsyncValidationPipeline`].
    pub const fn builder(
        key_provider: KP,
    ) -> ValidationPipelineBuilder<H, C, KP, AsyncValidators<H, C>> {
        ValidationPipelineBuilder::with_parts(key_provider, AsyncValidators(Vec::new()))
    }

    /// Verifies a JWT using the validation pipeline's key provider and validators.
    ///
    /// Steps run in the same order as [`ValidationPipeline::verify`]; the async
    /// validators run last, concurrently, and only once everything else has passed.
    ///
    /// # Errors
    ///
    /// - Any error listed for [`ValidationPipeline::verify`], with key resolutiovalidate
    ///   errors coming from the [`AsyncKeyProvider`].
    /// - Any [`JwtError`] raised by an [`AsyncTokenValidator`] which is included
    ///   in the validation pipeline. If several fail, the first to complete is returned.
    ///
    /// [`ValidationPipeline::verify`]: crate::validation::ValidationPipeline::verify
    pub async fn verify(&self, token: &[u8]) -> Result<(H, C), JwtError> {
        let token = self.core.decode(token)?;

        // the key is dropped before the async validators are awaited, so it need not be `Send`
        {
            let key =
                AsyncKeyProvider::resolve_key(&self.key_provider, &token.header, &token.claims)
                    .await?;
            self.core.validate(&token, &key)?;
        }

        try_join_all(
            self.async_validators
                .0
                .iter()
                .map(|v| v.validate_boxed(&token.header, &token.claims)),
        )
        .await?;

        Ok((token.header, token.claims))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            atomic::{
                AtomicBool,
                Ordering,
            },
        },
        task::{
            Context,
            Poll,
        },
    };

    use futures::executor::block_on;
    use serde::Deserialize;

    use crate::{
        Algorithm,
        JwtError,
        claims::Iss,
        header::{
            Alg,
            Kid,
        },
        validation::{
            AsyncKeyProvider,
            AsyncTokenValidator,
            AsyncValidationPipeline,
            StaticKeyProvider,
            VerificationKey,
            keystore::LocalKeystore,
        },
    };

    // header: {"alg":"HS256"}
    // claims: {"iss":"test-issuer"}
    const TOKEN: &[u8] = b"eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.";

    #[derive(Debug, Deserialize)]
    struct Header {
        alg: Algorithm,
        #[serde(default)]
        kid: String,
    }
    impl Alg for Header {
        fn alg(&self) -> Algorithm {
            self.alg
        }
    }
    impl Kid for Header {
        fn kid(&self) -> &str {
            &self.kid
        }
    }

    #[derive(Debug, Deserialize)]
    struct Claims {
        iss: Option<String>,
    }
    impl Iss for Claims {
        fn iss(&self) -> &str {
            self.iss.as_deref().unwrap_or("")
        }
    }

    struct MockKey {
        alg: Option<Algorithm>,
        valid_signature: bool,
    }
    impl MockKey {
        const fn valid() -> Self {
            Self {
                alg: Some(Algorithm::HS256),
                valid_signature: true,
            }
        }
    }
    impl VerificationKey for MockKey {
        fn alg(&self) -> Option<Algorithm> {
            self.alg
        }
        fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> {
            if self.valid_signature {
                Ok(())
            } else {
                Err(JwtError::InvalidSignature)
            }
        }
    }

    /// Returns [`Poll::Pending`] once, so tests exercise futures that actually suspend.
    struct YieldNow(bool);
    impl Future for YieldNow {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    const fn yield_now() -> YieldNow {
        YieldNow(false)
    }

    /// Native async provider handing out owned (`Arc`) keys.
    struct ArcKeyProvider(Arc<MockKey>);
    impl AsyncKeyProvider<Header, Claims> for ArcKeyProvider {
        type Key<'a> = Arc<MockKey>;
        async fn resolve_key<'a>(
            &'a self,
            _: &'a Header,
            _: &'a Claims,
        ) -> Result<Arc<MockKey>, JwtError> {
            yield_now().await;
            Ok(Arc::clone(&self.0))
        }
    }

    /// Records whether it was called, then accepts the token.
    struct CallRecorder(Arc<AtomicBool>);
    impl AsyncTokenValidator<Header, Claims> for CallRecorder {
        async fn validate(&self, _: &Header, _: &Claims) -> Result<(), JwtError> {
            yield_now().await;
            self.0.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct IssuerMustBe(&'static str);
    impl<H: Sync, C: Iss + Sync> AsyncTokenValidator<H, C> for IssuerMustBe {
        async fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
            yield_now().await;
            if claims.iss() == self.0 {
                Ok(())
            } else {
                Err(JwtError::CustomValidationError("async issuer mismatch"))
            }
        }
    }

    fn static_pipeline(
        key: MockKey,
    ) -> crate::validation::pipeline::ValidationPipelineBuilder<
        Header,
        Claims,
        StaticKeyProvider<MockKey>,
        super::AsyncValidators<Header, Claims>,
    > {
        AsyncValidationPipeline::builder(StaticKeyProvider::new(key))
    }

    fn assert_send<T: Send>(_: &T) {}

    #[test]
    fn valid_token_passes_sync_and_async_validators() {
        let called = Arc::new(AtomicBool::new(false));
        let pipeline = static_pipeline(MockKey::valid())
            .with_issuer_validator("test-issuer")
            .with_async(IssuerMustBe("test-issuer"))
            .with_async(CallRecorder(Arc::clone(&called)))
            .build();

        let future = pipeline.verify(TOKEN);
        assert_send(&future);
        let (header, claims) = block_on(future).unwrap();

        assert_eq!(header.alg, Algorithm::HS256);
        assert_eq!(claims.iss(), "test-issuer");
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn async_validator_error_propagates() {
        let pipeline = static_pipeline(MockKey::valid())
            .with_async(CallRecorder(Arc::new(AtomicBool::new(false))))
            .with_async(IssuerMustBe("other-issuer"))
            .build();

        let err = block_on(pipeline.verify(TOKEN)).unwrap_err();
        assert_eq!(
            err,
            JwtError::CustomValidationError("async issuer mismatch")
        );
    }

    #[test]
    fn sync_validator_error_propagates() {
        // header: {"alg":"HS256"}
        // claims: {"iss":"bad-test-issuer"}
        let token = b"eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJiYWQtdGVzdC1pc3N1ZXIifQ.";
        let pipeline = static_pipeline(MockKey::valid())
            .with_issuer_validator("test-issuer")
            .build();

        let err = block_on(pipeline.verify(token)).unwrap_err();
        assert_eq!(err, JwtError::WrongIssuer);
    }

    #[test]
    fn async_validators_skipped_when_signature_invalid() {
        let called = Arc::new(AtomicBool::new(false));
        let pipeline = static_pipeline(MockKey {
            alg: Some(Algorithm::HS256),
            valid_signature: false,
        })
        .with_async(CallRecorder(Arc::clone(&called)))
        .build();

        let err = block_on(pipeline.verify(TOKEN)).unwrap_err();
        assert_eq!(err, JwtError::InvalidSignature);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn async_validators_skipped_when_sync_validator_fails() {
        let called = Arc::new(AtomicBool::new(false));
        let pipeline = static_pipeline(MockKey::valid())
            .with_issuer_validator("other-issuer")
            .with_async(CallRecorder(Arc::clone(&called)))
            .build();

        let err = block_on(pipeline.verify(TOKEN)).unwrap_err();
        assert_eq!(err, JwtError::WrongIssuer);
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn header_alg_must_match_key_alg() {
        // header: {"alg":"HS512"}
        // claims: {"iss":"test-issuer"}
        let token = b"eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.";
        let pipeline = static_pipeline(MockKey::valid()).build();

        let err = block_on(pipeline.verify(token)).unwrap_err();
        assert_eq!(err, JwtError::WrongAlgorithm);
    }

    #[test]
    fn key_without_alg_returns_err() {
        let pipeline = static_pipeline(MockKey {
            alg: None,
            valid_signature: true,
        })
        .build();

        let err = block_on(pipeline.verify(TOKEN)).unwrap_err();
        assert_eq!(err, JwtError::UnsupportedAlgorithm);
    }

    #[test]
    fn input_above_size_limit_returns_err() {
        let pipeline = static_pipeline(MockKey::valid())
            .with_max_size(TOKEN.len())
            .build();
        block_on(pipeline.verify(TOKEN)).unwrap();

        let err = block_on(pipeline.verify(&[b'a'; 101])).unwrap_err();
        assert_eq!(err, JwtError::OverSizeThreshold);
    }

    #[test]
    fn local_keystore_resolves_by_kid() {
        let mut keystore = LocalKeystore::empty();
        keystore.add_key("key-a", MockKey::valid());
        let pipeline = AsyncValidationPipeline::<Header, Claims, _>::builder(keystore).build();

        // header: {"alg":"HS256","kid":"key-a"}
        // claims: {"iss":"test-issuer"}
        let token = b"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleS1hIn0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.";
        let (header, _) = block_on(pipeline.verify(token)).unwrap();
        assert_eq!(header.kid, "key-a");

        // header: {"alg":"HS256","kid":"key-b"}
        // claims: {"iss":"test-issuer"}
        let token = b"eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleS1iIn0.eyJpc3MiOiJ0ZXN0LWlzc3VlciJ9.";
        let err = block_on(pipeline.verify(token)).unwrap_err();
        assert_eq!(err, JwtError::VerificationKeyNotFound);
    }

    #[test]
    fn native_async_provider_with_owned_key() {
        let pipeline = AsyncValidationPipeline::builder(ArcKeyProvider(Arc::new(MockKey::valid())))
            .with_async(IssuerMustBe("test-issuer"))
            .build();

        let future = pipeline.verify(TOKEN);
        assert_send(&future);
        let (_, claims) = block_on(future).unwrap();
        assert_eq!(claims.iss(), "test-issuer");
    }

    #[test]
    fn decoding_errors_propagate() {
        let pipeline = static_pipeline(MockKey::valid()).build();

        let err = block_on(pipeline.verify(b"e30.e30.-=-")).unwrap_err();
        assert_eq!(err, JwtError::InvalidEncoding);

        // header: {}
        // claims: {}
        let err = block_on(pipeline.verify(b"e30.e30.")).unwrap_err();
        assert_eq!(err, JwtError::HeaderDeserialization);
    }
}
