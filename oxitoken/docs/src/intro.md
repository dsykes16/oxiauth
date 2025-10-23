# Introduction to OxiToken

`oxitoken` strives to be the fastest JWT encoding/decoding/validation library
while simulteneously providing the best developer experience and extensibility.
To that end, `oxitoken` does not force users into opinionated pre-defined header
or claims structs for JWTs.

## Defining a Header struct

The following is the minimum requirement for a JWT Header struct for OxiToken:

```rust
use oxitoken::{
    Algorithm,
    header::Alg,
};

// NOTE: serde::Deserialize is only required for decoding/validation
#[derive(serde::Deserialize, serde::Serialize)]
struct Header {
    alg: Algorithm
}
impl Alg for Header {
    fn alg(&self) -> Algorithm {
        self.alg
    }
}
```

Note the `Alg` trait. OxiToken uses a trait-based approach to support
user-defined header and claims structs for maximum performance and ease
of extensibility. Per [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1),
The only _required_ field in a JWT Header is the `alg` field.

## Defining a Claims struct

There are no required fields for JWT Claims, but for this example, we'll
implement the [`iss`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
(i.e. Issuer) claim.

```rust
use oxitoken::claims::Iss;

#[derive(serde::Deserialize, serde::Serialize)]
struct Claims {
    iss: String
}
impl Iss for Claims {
    fn iss(&self) -> &str {
        &self.iss
    }
}
```

## Cryptography

JWT's are cryptographically signed, so to make use of the above structs to
encode a JWT, we'll need a private key. `oxitoken` defaults to `aws_lc_rs` as
its cryptography provider, but it also supports OpenSSL and can be extended via
3rd-party crates to support any arbitrary cryptography provider. For this
example, we'll use `aws_lc_rs`.

```rust
use aws_lc_rs::{
    rsa::KeySize,
    signature::RsaKeyPair,
};


fn make_rsa_key() -> RsaKeyPair {
    RsaKeyPair::generate(KeySize::Rsa2048).unwrap()
}
```

## Encoding and Signing our first JWT

Now we'll tie together the above snippets of code and encode our first JWT
with OxiToken!

Note the additional import of `oxitoken::encoding::encode`. We also added some
convenience `new` constructors to our Claims and Header structs.

```rust
{{#include ../../examples/minimal_encode.rs}}
```

This example is available as the `minimal_encode` example and can be ran with:

`cargo run --example minimal_encode`

The output should be a Compact-Encoded JWT like this:

```text
JWT: eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJveGl0b2tlbi5leGFtcGxlLm9yZyJ9.jWRvDxhxo9vEtrA9myoI-8RPAj8WvYX_MTTqoOHy-SmqkSiRWq_WYugNo9fh4oY7C1hYjjaVnwsWyjoiPq3Rb2ccv4-ChKvheMI9fQQwGJB5I2wiLkwUJrQK0GQw9szHH0o0zx4CdsIzPE_1M0h5BbQh6EszKidm_dbM1T0De61lRh8j1M8uxmRnZFyE71mxfkZqw9qzDahZfFZbz05WiOUOawZ5S1eg3CAJxOT1jY68MwM6GKWAMC7Yr7XnSOu_80t31ier8G9s5DooVcqFZwSmAZWZGLltp5JSTo87NMRE0oMgp7OJNHCK2_fe3gm8UCRaNEhCX_sMAlTkpT_oJg
```

A Compact-Encoded JWT (commonly just called a JWT) is the JSON-serialized header,
JSON-serialized claims, and signature -- in that order -- base64-encoded and
delimited by periods.

## Decoding and Validating our first JWT

Validating JWTs with OxiToken is just as easy as encoding. OxiToken provides a
developer-friendly `ValidationPipeline` builder with a number of standard JWT
validators plus the ability to add any number of additional custom validators.

First, we need to convert our `aws_lc_rs::signature::Ed25519KeyPair`
into an `aws_lc_rs::signature::ParsedPublicKey`.

```rust
use aws_lc_rs::signature::{
    ED25519,
    Ed25519KeyPair,
    ParsedPublicKey,
}

fn make_parsed_public_key(key: &Ed25519KeyPair) -> ParsedPublicKey {
    ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap()
}
```

Now we can construct a `ValidationPipeline` using that public key to
validate and decode our JWT:

```rust
# use oxitoken::validation::{
#     ValidationPipeline,
#     StaticKeyProvider,
# }
# use aws_lc_rs::signature::{
#     ED25519,
#     Ed25519KeyPair,
#     KeyPair,
#     ParsedPublicKey,
# };
# 
# fn make_parsed_public_key(key: &Ed25519KeyPair) -> ParsedPublicKey {
#     ParsedPublicKey::new(&ED25519, key.public_key().as_ref()).unwrap()
# }

# fn main() {
    let pubkey = make_parsed_public_key(&key);
    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(pubkey.into())
            .with_issuer_validator("oxitoken.example.org")
            .build();

    let (decoded_header, decoded_claims) = validator.verify(jwt.as_bytes()).unwrap();
# }
```

The `ValidationPipeline` takes three generics, `<H, C, KP>`, where
H is the Header type, C is the Claims type, and KP is the KeyProvider.

This usage of generics permits us to define only the required fields for our specific
JWT use-case while also providing compile-time type checking for the specified validators.

### Header/Claims Getter Traits

An example is worth a thousand words here. If we try to add `exp` (Expiration)
validation to our `ValidationPipelin`, like this:

```rust,ignore
    let validator =
        ValidationPipeline::<Header, Claims, StaticKeyProvider<_>>::builder(pubkey.into())
            .with_issuer_validator("oxitoken.example.org")
            .with_expiration_validator()
            .build();
```

The result is a useful compile-time (rust-analyzer/IDE) error:

```text
Diagnostics:
1. the trait bound `Claims: Exp` is not satisfied
   unsatisfied trait bound [E0277]
```

If we want to validate expiration time, our Claims struct needs a getter for
the `exp` field, and the `exp` field itself of course.

```rust
use oxitoken::{
    claims::{
        Exp,
        Iss,
    },
};

#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct Claims {
    iss: String,
    exp: i64,
}
impl Claims {
    fn new(iss: impl Into<String>) -> Self {
        Self {
            iss: iss.into(),
            exp: 0,
        }
    }
}
impl Iss for Claims {
    fn iss(&self) -> &str {
        &self.iss
    }
}
impl Exp for Claims {
    fn exp(&self) -> i64 {
        self.exp
    }
}
```

### Key Provider

In our example above, we utilized a `StaticKeyProvider` for the `KP` (KeyProvider)
generic. The `StaticKeyProvider` is essentially a wrapper around a single
`VerificationKey`, it always returns the same key to the `ValidationPipeline`.
This is useful for testing and examples, but in the real-world keys are rotated,
and at any given time multiple keys may be active.

OxiToken was designed from the start with extensibility and real-world
usecases in mind. To that end, developers may implement their own KeyProvider,
and a reference `LocalKeystore` is provided as an example:

```rust
use std::collections::BTreeMap;

use crate::{
    JwtError,
    header::Kid,
    validation::{
        KeyProvider,
        VerificationKey,
    },
};

pub struct LocalKeystore<VK: VerificationKey> {
    keystore: BTreeMap<String, VK>,
}

impl<VK: VerificationKey> LocalKeystore<VK> {
    pub fn empty() -> Self {
        Self {
            keystore: BTreeMap::new(),
        }
    }
    pub fn add_key(&mut self, key_id: impl Into<String>, key: VK) {
        self.keystore.insert(key_id.into(), key);
    }
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
```

This permits developers to implement their own `KeyProvider`; anything from
a simple watched directory of public keys on the local filesystem, to a cached
set of JWKs from an OIDC discovery endpoint, or even a Cloud KMS or HSM. The
`resolve_key` method has full access to the header and claims of the JWT,
eliminating the overhead of parsing and decoding a JWT once to access the
relevant fields to select a key, and the re-parsing and decoding it during
the validation process as existing Rust JWT libraries do.

An excellent example is SPIFFE, where the `sub` of the JWT is the SPIFFE
ID, part of which determines which trust-domain the keys must be fetched
from. In that case, we could add the constraint `C: Sub` and have access
to the `claims.sub()` getter to make our key selection.

The `AsyncValidationPipeline` accepts an `AsyncKeyProvider`, which is
functionally identical aside from the `resolve_key` method being async.

### Custom Validators

Custom validators are first-class citizens in OxiToken. With the exception
of `alg` validation, which is non-optional per [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2),
all validation in OxiToken is performed via `TokenValidator` implementations.

The `.with_issuer_validator(...)` in the example above simply adds a `IssuerValidator`
to the `ValidationPipeline`.

The `IssuerValidator` is implemented like:

```rust,ignore
pub struct IssuerValidator {
    expected_issuer: String,
}
impl IssuerValidator {
    pub(crate) fn new(iss: String) -> Self {
        Self {
            expected_issuer: iss,
        }
    }
}
impl<H, C> TokenValidator<H, C> for IssuerValidator
where
    C: Iss,
{
    fn validate(&self, _: &H, claims: &C) -> Result<(), JwtError> {
        if self.expected_issuer == claims.iss() {
            Ok(())
        } else {
            Err(JwtError::WrongIssuer)
        }
    }
}
```

Imagine a scenario where we need to accept JWTs from multiple issuers. Instead of
juggling multiple ValidationPipelines, we can simply implement an altnerative
`IssuerValidator` like this:

```rust
use std::collections::HashSet;
use oxitoken::{
    claims::{
        Iss,
    },
    error::JwtError,
    validation::{
        TokenValidator,
    },
};

{{#include ../../examples/custom_validators.rs:impl}}
```

We can then inject this custom validator into a validation pipeline like so:

```rust
{{#include ../../examples/custom_validators.rs:usage}}
```

The `.with(...)` method supports adding any number of arbitrary `TokenValidator`
implementations. The example given here is static, but a `TokenValidator` need
not be static, an excellent example being `jti` (JWT ID) validation. The `jti`
is intended to permit limiting token re-use and/or instant revocation.
In real-world systems, this usually means checking an external datastore like
Redis or ValKey, usually along with caching a local copy of the revocation list
or a bloom filter. The `iat` claim can be used to assist in determining if the
local data is "fresh" enough to make an immediate decision or if a remote network
call is required.

A crude example of a revocation validator is:

Validator:

```rust
{{#include ../../examples/revocation.rs:impl}}
```

Usage:

```rust
{{#include ../../examples/revocation.rs:usage}}
```

While OxiToken strives to be a drop-in production-ready solution, revocation via
`jti` is inherently a complex solution that tends to be heavily dependent on existing
infrastructure, so no off-the-shelf solution is provided at this time as there
is no one-size-fits-all solution to JWT revocation.
