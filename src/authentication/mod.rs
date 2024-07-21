use std::{
    collections::{HashMap, HashSet}, convert::Infallible, future::Future, pin::Pin, task::{Context, Poll}
};

use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    middleware::AddExtension,
    response::{IntoResponse, IntoResponseParts, Response},
    Extension,
};
use tower::{Layer, Service};

pub mod backends;

/// Marker trait transformed user credentials, proof of authentication
///
/// For basic auth this is the same as Credentials
/// For JWT auth this is the JWT
/// For oauth this is the access token
/// For session based auth is used only to identify the user
pub trait AuthProof: std::fmt::Debug + Clone + Send + Sync + 'static {
    type Error: std::error::Error;

    fn from_bytes(bytes: Bytes) -> Result<Self, Self::Error>;
}

/// Represents a change in authentication state for an user
#[derive(Debug, Clone)]
pub enum AuthStateChange<T: AuthProof> {
    LoggedIn(T),
    LoggedOut(T),
}

#[derive(Debug, Clone)]
pub enum AuthUser<User> {
    Authenticated(User),
    Unaunthenticated,
}

#[async_trait]
impl<User: Send + Sync + Clone + 'static, S> FromRequestParts<S> for AuthUser<User> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuthUser<User>>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract auth user service. Is AuthenticationService layer enabled?",
        ))
    }
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


pub trait User {
    fn roles(&self) -> HashSet<String> {
        HashSet::new()
    }
}


#[async_trait]
pub trait AuthenticationBackend: std::fmt::Debug + Clone + Send + Sync {
    type AuthProof: AuthProof;
    type Credentials: Send + Sync;
    type Error: std::error::Error + Send + Sync + IntoResponse;
    type User: Send + Sync + Clone + User;

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
    ) -> Result<AuthUser<Self::User>, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct AuthenticationService<Backend: AuthenticationBackend> {
    backend: Backend,
}

impl<Backend: AuthenticationBackend> AuthenticationService<Backend> {
    pub fn new(backend: Backend) -> Self {
        Self { backend }
    }
}

impl<Backend: AuthenticationBackend> AuthenticationService<Backend> {
    /// Logs in user
    ///
    /// Should be called in login route handlers and returned in response to propagate changes to transform layer
    pub async fn login(
        &mut self,
        credentials: Backend::Credentials,
    ) -> Result<AuthStateChange<Backend::AuthProof>, Backend::Error> {
        self.backend.login(credentials).await
    }

    /// Logs out user
    ///
    /// Should be called in logout route handlers and returned in response to propagate changes to transform layer.
    pub async fn logout(
        &mut self,
        auth_proof: Backend::AuthProof,
    ) -> Result<AuthStateChange<Backend::AuthProof>, Backend::Error> {
        self.backend.logout(auth_proof).await
    }

    /// Verifies [crate::authentication::AuthProof] and returns the authenticated user
    async fn authenticate(
        &mut self,
        auth_proof: Backend::AuthProof,
    ) -> Result<AuthUser<Backend::User>, Backend::Error> {
        self.backend.authenticate(auth_proof).await
    }
}

#[async_trait]
impl<S, B: AuthenticationBackend + 'static> FromRequestParts<S> for AuthenticationService<B>
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticationService<B>>()
            .cloned()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't extract authentication service. Is AuthenticationServiceLayer enabled?",
            ))
    }
}

#[derive(Debug, Clone)]
pub struct AuthManagerService<S, Backend: AuthenticationBackend> {
    inner: S,
    auth_service: AuthenticationService<Backend>,
}

impl<S, Backend: AuthenticationBackend> AuthManagerService<S, Backend> {
    pub fn new(inner: S, auth_service: AuthenticationService<Backend>) -> Self {
        AuthManagerService {
            inner,
            auth_service: auth_service,
        }
    }
}

/// A middleware that provides [`AuthSession`] as a request extension.
impl<S, Backend> Service<Request> for AuthManagerService<S, Backend>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    Backend: AuthenticationBackend + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut auth_service = self.auth_service.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let auth_proof = req.extensions().get::<Backend::AuthProof>();

            if let Some(auth_proof) = auth_proof {
                match auth_service.authenticate(auth_proof.clone()).await {
                    Ok(user) => {
                        req.extensions_mut().insert(user);
                    }
                    Err(err) => {
                        return Ok(err.into_response());
                    }
                };
            } else {
                req.extensions_mut()
                    .insert(AuthUser::<Backend::User>::Unaunthenticated);
                println!("No auth proof");
            }

            req.extensions_mut().insert(auth_service);

            let resp = inner.call(req).await?;
            Ok(resp)
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthManagerLayer<Backend>
where
    Backend: AuthenticationBackend,
{
    auth_service: AuthenticationService<Backend>,
}

impl<Backend> AuthManagerLayer<Backend>
where
    Backend: AuthenticationBackend,
{
    pub fn new(backend: Backend) -> Self {
        Self {
            auth_service: AuthenticationService::new(backend),
        }
    }
}

impl<S, Backend> Layer<S> for AuthManagerLayer<Backend>
where
    Backend: AuthenticationBackend,
{
    type Service = AuthManagerService<S, Backend>;

    fn layer(&self, service: S) -> Self::Service {
        AuthManagerService::new(service, self.auth_service.clone())
    }
}
