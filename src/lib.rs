//! An authentication and authorization crate for `axum`.
//!
//! Provides a generic way to control the authentication and authorization flow
//! of both `tower` `Service`s and of `axum` routes.

/// Contains authentication layer core traits and implementations.
pub mod authn;
/// Contains authorization layer core traits and implementations.
pub mod authz;

pub use authn::{Authn, AuthnBackend, AuthnLayer, AuthnStateChange, AuthnUser, extractors::*};
pub use authz::{AuthzBackend, AuthzBuilder, AuthzLayer};