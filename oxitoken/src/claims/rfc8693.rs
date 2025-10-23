//! Traits representing authorization-relevant JWT Claims defined
//! in RFC 8693 (OAuth 2.0 Token Exchange)

use std::hash::Hash;

/// `act` (Actor) Claim
///
/// Ref: [RFC 8693 4.1](<https://datatracker.ietf.org/doc/html/rfc8693#actor>)
pub trait Act {
    /// Type to be returned as reference to `act` field of JWS (e.g. `str`)
    type Actor: Hash + PartialEq + ?Sized;

    /// Return `act` (Actor) claim from JWS
    fn act(&self) -> &Self::Actor;
}

/// `scope` (Scopes) Claim
///
/// Ref: [RFC 8693 4.2](<https://datatracker.ietf.org/doc/html/rfc8693#scopes>)
pub trait Scope {
    /// `scope` (Scopes) claim from JWS
    fn scope(&self) -> &[&str];
}

/// `client_id` (Client Identifier) Claim
///
/// Ref: [RFC 8693 4.3](<https://datatracker.ietf.org/doc/html/rfc8693#client_id>)
pub trait ClientId {
    /// `client_id` (Client Identifier) claim from JWS
    fn client_id(&self) -> &str;
}

/// `may_act` (Authorized Actor) Claim
///
/// Ref: [RFC 8693 4.4](<https://datatracker.ietf.org/doc/html/rfc8693#may_act>)
pub trait MayAct {
    /// Type to be returned as reference to `may_act` field of JWS (e.g. `str`)
    type AuthorizedActor: Hash + PartialEq + ?Sized;
    /// Return `may_act` (Authorized Actor) claim from JWS
    fn may_act(&self) -> &Self::AuthorizedActor;
}
