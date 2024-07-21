use std::{
    collections::HashSet,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    async_trait,
    extract::Request,
    http::request::Parts,
    response::{IntoResponse, Response},
    RequestExt,
};
use backends::{
    and_authorization_backend::AndAuthorizationBackend,
    or_authorization_backend::OrAuthorizationBackend,
};
use tower::{Layer, Service};

use crate::authentication::User;

pub mod backends;

/// Represents a backend for authorization
///
/// User
#[async_trait]
pub trait AuthorizationBackend<AuthzUser: User + Send + Sync>:
    std::fmt::Debug + Clone + Send + Sync
{
    type Error: std::error::Error + Send + Sync + IntoResponse;

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct AuthorizationBuilder<U: User + Send + Sync, B: AuthorizationBackend<U>> {
    authorization_backend: B,
    _marker: PhantomData<U>,
}

impl<U: User + Send + Sync, B1: AuthorizationBackend<U>> AuthorizationBuilder<U, B1> {
    pub fn new(authorization_backend: B1) -> Self {
        AuthorizationBuilder {
            authorization_backend,
            _marker: PhantomData,
        }
    }

    pub fn and<B2: AuthorizationBackend<U>>(
        self,
        authorization_backend: B2,
    ) -> AuthorizationBuilder<U, AndAuthorizationBackend<B1, B2>> {
        let backend =
            AndAuthorizationBackend::new(self.authorization_backend, authorization_backend);

        AuthorizationBuilder {
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }

    pub fn or<B2: AuthorizationBackend<U>>(
        self,
        authorization_backend: B2,
    ) -> AuthorizationBuilder<U, OrAuthorizationBackend<B1, B2>> {
        let backend =
            OrAuthorizationBackend::new(self.authorization_backend, authorization_backend);

        AuthorizationBuilder {
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }

    pub fn build(self) -> AuthorizationLayer<U, B1> {
        AuthorizationLayer {
            authorization_backend: self.authorization_backend,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationService<S, U: User + Send + Sync, B: AuthorizationBackend<U>> {
    inner: S,
    authorization_backend: B,
    _marker: PhantomData<U>,
}

impl<U, B> AuthorizationLayer<U, B>
where
    B: AuthorizationBackend<U>,
    U: User + Send + Sync,
{
    pub fn new(backend: B) -> Self {
        Self {
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }
}

impl<S, U, B> AuthorizationService<S, U, B>
where
    B: AuthorizationBackend<U>,
    U: User + Send + Sync,
{
    pub fn new(service: S, backend: B) -> Self {
        Self {
            inner: service,
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }
}

impl<S, U, B> Service<Request> for AuthorizationService<S, U, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    U: User + Send + Sync + 'static,
    B: AuthorizationBackend<U> + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut backend = self.authorization_backend.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let (parts, body) = req.into_parts(); // TODO: Check if there is a better way

            let authorized = match backend.authorize(&parts).await {
                Ok(authorized) => authorized,
                Err(err) => return Ok(err.into_response()),
            };

            if !authorized {
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

#[derive(Debug, Clone)]
pub struct AuthorizationLayer<U: User + Send + Sync, B: AuthorizationBackend<U>> {
    authorization_backend: B,
    _marker: PhantomData<U>,
}

impl<S, U, B> Layer<S> for AuthorizationLayer<U, B>
where
    B: AuthorizationBackend<U>,
    U: User + Send + Sync,
{
    type Service = AuthorizationService<S, U, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthorizationService::new(service, self.authorization_backend.clone())
    }
}
