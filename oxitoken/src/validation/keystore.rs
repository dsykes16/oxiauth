//! Provides a reference [`LocalKeystore`] which implements the [`KeyProvider`] trait
use std::collections::BTreeMap;

use crate::{
    JwtError,
    header::Kid,
    validation::{
        KeyProvider,
        VerificationKey,
    },
};

/// In-memory [`KeyProvider`] implementation that determines key
/// association via the `kid` JWT header parameter.
pub struct LocalKeystore<VK: VerificationKey> {
    keystore: BTreeMap<String, VK>,
}
impl<VK: VerificationKey> LocalKeystore<VK> {
    /// Instantiates a new, empty [`LocalKeystore`]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            keystore: BTreeMap::new(),
        }
    }

    /// Adds a [`VerificationKey`] to the [`LocalKeystore`] instance
    pub fn add_key(&mut self, key_id: impl Into<String>, key: VK) {
        self.keystore.insert(key_id.into(), key);
    }

    /// Removes a [`VerificationKey`] from the [`LocalKeystore`] instance
    pub fn remove_key(&mut self, key_id: impl AsRef<str>) {
        self.keystore.remove(key_id.as_ref());
    }
}

impl<H, C, VK> KeyProvider<H, C> for LocalKeystore<VK>
where
    H: Kid,
    VK: VerificationKey,
{
    type Key = VK;

    fn resolve_key(&self, header: &H, _: &C) -> Result<&VK, JwtError> {
        self.keystore
            .get(header.kid())
            .ok_or(JwtError::VerificationKeyNotFound)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use crate::{
        Algorithm,
        error::JwtError,
        header::Kid,
        validation::{
            KeyProvider,
            VerificationKey,
            keystore::LocalKeystore,
        },
    };

    struct Claims;
    #[derive(Debug)]
    struct Header {
        kid: String,
    }
    impl Header {
        fn new(key_id: impl Into<String>) -> Self {
            Self { kid: key_id.into() }
        }
    }
    impl Kid for Header {
        fn kid(&self) -> &str {
            &self.kid
        }
    }

    #[derive(Debug)]
    struct MockKey {
        id: char,
    }
    impl MockKey {
        fn new(id: char) -> Self {
            Self { id }
        }
    }
    impl VerificationKey for MockKey {
        fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), JwtError> {
            Ok(())
        }
        fn alg(&self) -> Option<Algorithm> {
            Some(Algorithm::HS256)
        }
    }

    #[test]
    fn test_local_keystore() {
        let key_a = MockKey::new('a');
        let key_b = MockKey::new('b');

        let mut key_provider = LocalKeystore::empty();
        key_provider.add_key("key_a", key_a);
        key_provider.add_key("key_b", key_b);

        let key_a = key_provider
            .resolve_key(&Header::new("key_a"), &Claims)
            .unwrap();
        let key_b = key_provider
            .resolve_key(&Header::new("key_b"), &Claims)
            .unwrap();

        assert_eq!(key_a.id, 'a');
        assert_eq!(key_b.id, 'b');

        key_provider.remove_key("key_b");

        let err = key_provider
            .resolve_key(&Header::new("key_b"), &Claims)
            .unwrap_err();
        assert_eq!(err, JwtError::VerificationKeyNotFound);
    }
}
