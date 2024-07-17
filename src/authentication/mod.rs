use std::convert::Infallible;

use axum::{
    async_trait,
    body::Bytes,
    response::{IntoResponse, IntoResponseParts},
};

pub mod backends;

/// Marker trait transformed user credentials, proof of authentication
///
/// For basic auth this is the same as Credentials
/// For JWT auth this is the JWT
/// For oauth this is the access token
/// For session based auth is used only to identify the user
pub trait AuthProof: std::fmt::Debug + Clone + Send + Sync + TryFrom<Bytes> + 'static {}

/// Represents a change in authentication state for an user
#[derive(Debug, Clone)]
pub enum AuthStateChange<T: AuthProof> {
    LoggedIn(T),
    LoggedOut(T),
}

impl<T: AuthProof> IntoResponseParts for AuthStateChange<T> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        res.extensions_mut().insert(self);
        Ok(res)
    }
}

#[async_trait]
pub trait AuthenticationBackend: std::fmt::Debug + Clone + Send + Sync {
    type AuthProof: AuthProof;
    type Credentials: Send + Sync; // dodat parsiranje iz reqparts, vjerojatno, napraviti extractor
    type Error: std::error::Error + Send + Sync + IntoResponse;
    type User: Send + Sync;

    /// Logs in user
    ///
    /// Should be called in login route handlers and returned in response to propagate changes to transform layer
    async fn login(
        &mut self,
        // ili requset: direkt
        _credentials: Self::Credentials,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error>;

    /// Logs out user
    ///
    /// Should be called in logout route handlers and returned in response to propagate changes to transform layer.
    async fn logout(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error>;

    /// Verifies [crate::authentication::AuthProof] and returns the authenticated user
    async fn authenticate(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<Self::User, Self::Error>;
}
