pub mod backends;


use std::{
    collections::HashSet,
    future::Future,
    hash::Hash,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, Request},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};
#[derive(Debug, Clone)]
pub enum AuthStateChange<T: AuthenticationProof> {
    LoggedIn(T),
    LoggedOut(T),
}

pub trait AuthenticationProof: std::fmt::Debug + Clone + Send + Sync + TryFrom<String /* vec<u8>, bytes instead of this */> {
    type Id: Eq + Hash;

    /// id is used for unique indetification of authentication proof, used within session
    fn id(&self) -> Self::Id;
}

// impl Into<ResponseParts> for AuthState
#[async_trait]
pub trait AuthenticationBackend: std::fmt::Debug + Clone + Send + Sync {
    type AuthenticationProof: AuthenticationProof;
    type Credentials: Send + Sync; // dodat parsiranje iz reqparts, vjerojatno, napraviti extractor
    type Error: std::error::Error + Send + Sync + IntoResponse;
    type User: Send + Sync;

    /// Logins user and returns LoggedIn AuthState variant
    ///
    /// Unimplemented by default
    async fn login(
        &mut self,
        // ili requset: direkt
        _credentials: Self::Credentials,
    ) -> Result<AuthStateChange<Self::AuthenticationProof>, Self::Error>;

    /// Logs out user and returns LoggedOut AuthState variant
    ///
    /// Unimpmeneted by default
    async fn logout(
        &mut self,
        _authentication_proof: Self::AuthenticationProof,
    ) -> Result<AuthStateChange<Self::AuthenticationProof>, Self::Error>;
    
    /// Verifies authentication proof and returns the authenticated user
    ///
    /// For session auth does no verificaiton, instead only extracts user, since if session is valid user is valid
    async fn authenticate(
        &mut self,
        authenticationProof: Self::AuthenticationProof,
    ) -> Result<Self::User, Self::Error>;
}

#[async_trait]
pub trait AuthSessionBackend<AuthnProof: AuthenticationProof>:
    std::fmt::Debug + Clone + Send + Sync
{
    type Error: Send + Sync + IntoResponse;


    async fn extract_authentication_proof(
        &mut self,
        mut request: Request,
    ) -> Result<Request, Self::Error>;

    async fn process_auth_state_change(
        &mut self,
        mut response: Response,
    ) -> Result<Response, Self::Error>;
}

#[async_trait]
pub trait AuthorizationBackend: std::fmt::Debug + Clone + Send + Sync {
    type Error: std::error::Error + Send + Sync + IntoResponse;
    type User: Send + Sync;
    type Permission: Hash + Eq + Send + Sync;

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn authorize(
        &self,
        user: &Self::User,
        perm: Self::Permission,
    ) -> Result<bool, Self::Error> {
        Ok(self.get_all_permissions(user).await?.contains(&perm))
    }

    /// Gets the permissions for the provided user.
    async fn get_user_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    /// Gets the group permissions for the provided user.
    async fn get_group_permissions(
        &self,
        _user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        Ok(HashSet::new())
    }

    /// Gets all permissions for the provided user.
    async fn get_all_permissions(
        &self,
        user: &Self::User,
    ) -> Result<HashSet<Self::Permission>, Self::Error> {
        let mut all_perms = HashSet::new();
        all_perms.extend(self.get_user_permissions(user).await?);
        all_perms.extend(self.get_group_permissions(user).await?);
        Ok(all_perms)
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionService<S, AuthnProof, Backend>
where
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof>,
{
    inner: S,
    backend: Backend,
    _marker: PhantomData<AuthnProof>,
}

impl<S, AuthnProof, Backend> AuthSessionService<S, AuthnProof, Backend>
where
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof>,
{
    pub fn new(inner: S, backend: Backend) -> Self {
        Self {
            inner,
            backend,
            _marker: PhantomData,
        }
    }
}

/// A middleware that provides [`AuthSession`] as a request extension.
impl<S, Backend, AuthnProof> Service<Request> for AuthSessionService<S, AuthnProof, Backend>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof> + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut backend = self.backend.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let req = match backend.extract_authentication_proof(req).await {
                Ok(req) => req,
                Err(err) => {
                    return Ok(err.into_response());
                }
            };

            let resp = inner.call(req).await?;

            let resp = match backend.process_auth_state_change(resp).await {
                Ok(resp) => resp,
                Err(err) => {
                    return Ok(err.into_response());
                }
            };

            Ok(resp)
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionLayer<AuthnProof, Backend>
where
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof>,
{
    backend: Backend,
    _marker: PhantomData<AuthnProof>,
}

impl<AuthnProof, Backend> AuthSessionLayer<AuthnProof, Backend>
where
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof>,
{
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthnProof, Backend> Layer<S> for AuthSessionLayer<AuthnProof, Backend>
where
    AuthnProof: AuthenticationProof,
    Backend: AuthSessionBackend<AuthnProof>,
{
    type Service = AuthSessionService<S, AuthnProof, Backend>;

    fn layer(&self, service: S) -> Self::Service {
        AuthSessionService::new(service, self.backend.clone())
    }
}

#[cfg(test)]
mod tests {}
