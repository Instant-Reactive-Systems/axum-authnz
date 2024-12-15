//! Contains authentication layer core traits and their implementations

pub mod backends;
pub mod extractors;

use axum::{
    async_trait,
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, IntoResponseParts, Response},
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// Represents a change in a user's authentication state.
#[derive(Debug, Clone)]
pub enum AuthnStateChange<AuthnProof> {
    LoggedIn(AuthnProof),
    LoggedOut(AuthnProof),
}

impl<AuthnProof> IntoResponseParts for AuthnStateChange<AuthnProof>
where
    AuthnProof: Clone + Send + Sync + 'static,
{
    type Error = Infallible;

    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        res.extensions_mut().insert(self);
        Ok(res)
    }
}

/// Represents an authenticated or anonymous user.
#[derive(Debug, Clone)]
pub enum User<UserData> {
    /// Authenticated user with his own data.
    Authn(AuthnUser<UserData>),
    /// Anonymous user.
    Anon,
}

/// Authenticated user and its data
// TODO: Should data be in arc?
#[derive(Debug, Clone)]
pub struct AuthnUser<UserData>(pub UserData);

#[async_trait]
impl<UserData, S> FromRequestParts<S> for User<UserData>
where
    UserData: Clone + Send + Sync + 'static,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<User<UserData>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract User. Is AuthnLayer enabled?",
        ))
    }
}

#[async_trait]
impl<UserData, S> FromRequestParts<S> for AuthnUser<UserData>
where
    UserData: Clone + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthnUser<UserData>>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

/// Trait for representing an arbitrary authentication backend.
///
/// The authentication backend is responsible for handling login/logout requests and verifying authentication proof which is extracted by the transform layer.
#[async_trait]
pub trait AuthnBackend: std::fmt::Debug + Clone + Send + Sync + 'static {
    type AuthnProof: Clone + Send + Sync + 'static;
    type Error: Send + Sync + IntoResponse;
    type UserData: Send + Sync + Clone + 'static;

    /// Verifies the provided [`crate::authentication::AuthnProof`] and returns a [`User`].
    ///
    /// # Note
    /// Authorization should not be implemented in this layer, instead use authorization layer with [crate::authorization::backends::login_backend].
    async fn authenticate(
        &mut self,
        authn_proof: Self::AuthnProof,
    ) -> Result<User<Self::UserData>, Self::Error>;
}

/// A request extension that exposes a way to interact with the [`AuthnBackend`].
#[derive(Debug, Clone)]
pub struct Authn<B: AuthnBackend> {
    backend: B,
}

impl<B: AuthnBackend> Authn<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: AuthnBackend> std::ops::Deref for Authn<B> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.backend
    }
}

impl<B: AuthnBackend> std::ops::DerefMut for Authn<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.backend
    }
}

#[async_trait]
impl<S, B> FromRequestParts<S> for Authn<B>
where
    S: Send + Sync,
    B: AuthnBackend,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract Authn extension. Is AuthnLayer enabled?",
        ))
    }
}

/// A [`tower::Service`] that wraps a different [`tower::Service`] and infuses a [`User`] into the request extensions
/// depending on whether a valid [`AuthnProof`] was provided.
#[derive(Debug, Clone)]
pub struct AuthnService<S, B: AuthnBackend> {
    inner: S,
    authn_extension: Authn<B>,
}

impl<S, B: AuthnBackend> AuthnService<S, B> {
    pub fn new(inner: S, authn_extension: Authn<B>) -> Self {
        Self {
            inner,
            authn_extension,
        }
    }
}

/// A middleware that provides a `AuthnService` as a request extension.
impl<S, B> Service<Request> for AuthnService<S, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: AuthnBackend + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut authn_extension = self.authn_extension.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let authn_proof = req.extensions().get::<B::AuthnProof>();

            if let Some(authn_proof) = authn_proof {
                match authn_extension.authenticate(authn_proof.clone()).await {
                    Ok(user) => req.extensions_mut().insert(user),
                    Err(err) => return Ok(err.into_response()),
                };
            } else {
                req.extensions_mut().insert(User::<B::UserData>::Anon);
            }

            req.extensions_mut().insert(authn_extension);

            let resp = inner.call(req).await?;
            Ok(resp)
        })
    }
}

/// Authentication layer to pass to `axum`.
#[derive(Debug, Clone)]
pub struct AuthnLayer<B: AuthnBackend> {
    authn_extension: Authn<B>,
}

impl<B> AuthnLayer<B>
where
    B: AuthnBackend,
{
    pub fn new(backend: B) -> Self {
        Self {
            authn_extension: Authn::new(backend),
        }
    }
}

impl<S, B> Layer<S> for AuthnLayer<B>
where
    B: AuthnBackend,
{
    type Service = AuthnService<S, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthnService::new(service, self.authn_extension.clone())
    }
}
