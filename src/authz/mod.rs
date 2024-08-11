//! Contains authorization layer core traits and implementations.

pub mod backends;

use axum::{
    async_trait,
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use backends::combinators::{AndAuthzBackend, OrAuthzBackend};

/// Trait for representing an arbitrary authorization backend.
#[async_trait]
pub trait AuthzBackend<U>: std::fmt::Debug + Clone + Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + IntoResponse;

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error>;
}

/// Builder used for combining multiple authorization backends into a single [crate::authorization::AuthorizationLayer]
#[derive(Debug, Clone)]
pub struct AuthzBuilder<U, B: AuthzBackend<U>> {
    authz_backend: B,
    _marker: PhantomData<U>,
}

impl<U, B1: AuthzBackend<U>> AuthzBuilder<U, B1> {
    /// Creates a new instance of the builder with the provided authorization backend
    pub fn new(authz_backend: B1) -> Self {
        AuthzBuilder {
            authz_backend,
            _marker: PhantomData,
        }
    }

    /// Combines the current authorization backend with the provided authorization backend inside an [authorization::backend::and_authorization_backend::AndAuthorizationBackend]
    pub fn and<B2: AuthzBackend<U>>(
        self,
        authz_backend: B2,
    ) -> AuthzBuilder<U, AndAuthzBackend<B1, B2>> {
        let authz_backend = AndAuthzBackend::new(self.authz_backend, authz_backend);

        AuthzBuilder {
            authz_backend,
            _marker: PhantomData,
        }
    }

    /// Combines the current authorization backend with the provided authorization backend inside an [authorization::backend::or_authorization_backend::OrAuthorizationBackend]
    pub fn or<B2: AuthzBackend<U>>(
        self,
        authz_backend: B2,
    ) -> AuthzBuilder<U, OrAuthzBackend<B1, B2>> {
        let authz_backend = OrAuthzBackend::new(self.authz_backend, authz_backend);

        AuthzBuilder {
            authz_backend,
            _marker: PhantomData,
        }
    }

    /// Consumes the builder to build the [crate::authorization::AuthorizationLayer]
    pub fn build(self) -> AuthzLayer<U, B1> {
        AuthzLayer {
            authz_backend: self.authz_backend,
            _marker: PhantomData,
        }
    }
}

/// A [`tower::Service`] that wraps a different [`tower::Service`] and allows or denies requests based on
/// the decision made by the authorization backend.
#[derive(Debug, Clone)]
pub struct AuthzService<S, U, B: AuthzBackend<U>> {
    inner: S,
    authz_backend: B,
    _marker: PhantomData<U>,
}

impl<S, U, B> AuthzService<S, U, B>
where
    B: AuthzBackend<U>,
{
    pub fn new(service: S, backend: B) -> Self {
        Self {
            inner: service,
            authz_backend: backend,
            _marker: PhantomData,
        }
    }
}

impl<S, U, B> Service<Request> for AuthzService<S, U, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: AuthzBackend<U> + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let backend = self.authz_backend.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = req.into_parts(); // TODO: Check if there is a better way

            //TODO: Should we limit ourselves to $parts instead of the full request, maybe not, maybe its better to pass in whole request and return it
            let authorized = match backend.authorize(&parts).await {
                Ok(authorized) => authorized,
                Err(err) => return Ok(err.into_response()),
            };

            if !authorized {
                // TODO: Allow customizing unauthorized response
                let mut response = Response::default();
                *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
                return Ok(response);
            }

            let req = Request::from_parts(parts, body);

            let resp = inner.call(req).await?;
            Ok(resp)
        })
    }
}

/// Authorization layer to pass to `axum`.
#[derive(Debug, Clone)]
pub struct AuthzLayer<U, B: AuthzBackend<U>> {
    authz_backend: B,
    _marker: PhantomData<U>,
}

impl<U, B> AuthzLayer<U, B>
where
    B: AuthzBackend<U>,
{
    /// Creates a new instance of AuthzLayer with the provided backend.
    ///
    /// Consider using [crate::authorization::AuthorizationBuilder] if you are using complex
    /// authorization backends.
    pub fn new(backend: B) -> Self {
        Self {
            authz_backend: backend,
            _marker: PhantomData,
        }
    }
}

impl<S, U, B> Layer<S> for AuthzLayer<U, B>
where
    B: AuthzBackend<U>,
{
    type Service = AuthzService<S, U, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthzService::new(service, self.authz_backend.clone())
    }
}
