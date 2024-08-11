//! An authentication and authorization crate for `axum`.
//!
//! Provides a generic way to control the authentication and authorization flow
//! of both `tower` `Service`s and of `axum` routes.

/// Contains authentication layer core traits and implementations.
pub mod authn;
/// Contains authorization layer core traits and implementations.
pub mod authz;
/// Contains transform layer core traits and implementations.
pub mod transform;

pub use authn::{Authn, AuthnBackend, AuthnLayer, AuthnStateChange, User};
pub use authz::{AuthzBackend, AuthzBuilder, AuthzLayer};
pub use transform::{AuthProofTransformer, AuthProofTransformerLayer};
