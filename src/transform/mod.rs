//! Contains transform layer core traits and implementations.

pub mod backends;

use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    async_trait,
    extract::Request,
    response::{IntoResponse, Response},
};

use tower::{Layer, Service};

/// Extracts and inserts (transforms) an authentication proof from requests and responses.
///
/// Used as a layer to transform different types of client-side provided data into
/// an authentication proof.
///
/// For example:
///     - HeaderAuthnProofTransformer extracts an authentication proof
///       from the request header using no state, ignores login/logout event,
///       useful for services that only do authentication with no login/logout flows.
///     - SessionAuthnProofTransformer extracts an authentication proof from http sessions
///       using tower sessions and creates/destroys the session upon login/logout requests.
#[async_trait]
pub trait AuthnProofTransformer<AuthnProof>: std::fmt::Debug + Clone + Send + Sync + 'static {
    type Error: Send + Sync + IntoResponse;

    /// Inserts an authentication proof into the request and returns the modified request
    /// with the authentication proof inserted into the request extensions.
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_authn_proof(&mut self, request: Request) -> Result<Request, Self::Error>;

    /// Receives and handles an [`crate::authn::AuthStateChange`] from the response extensions.
    ///
    /// For example, for session based auth and the LoggedIn event,
    /// we would insert a new session and return the modified response
    /// which contains the session id.
    async fn process_authn_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error>;
}

/// A request extension that exposes a way to interact with the [`AuthnProofTransformer`].
#[derive(Debug, Clone)]
pub struct AuthnProofTransformerService<S, AuthnProof, B>
where
    B: AuthnProofTransformer<AuthnProof>,
{
    inner: S,
    backend: B,
    _marker: PhantomData<AuthnProof>,
}

impl<S, AuthnProof, B> AuthnProofTransformerService<S, AuthnProof, B>
where
    B: AuthnProofTransformer<AuthnProof>,
{
    pub fn new(inner: S, backend: B) -> Self {
        Self {
            inner,
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthnProof, B> Service<Request> for AuthnProofTransformerService<S, AuthnProof, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: AuthnProofTransformer<AuthnProof> + 'static,
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
            let req = match backend.insert_authn_proof(req).await {
                Ok(req) => req,
                Err(err) => return Ok(err.into_response()),
            };

            let resp = inner.call(req).await?;

            let resp = match backend.process_authn_state_change(resp).await {
                Ok(resp) => resp,
                Err(err) => return Ok(err.into_response()),
            };

            Ok(resp)
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthnProofTransformerLayer<AuthnProof, B>
where
    B: AuthnProofTransformer<AuthnProof>,
{
    backend: B,
    _marker: PhantomData<AuthnProof>,
}

impl<AuthnProof, B> AuthnProofTransformerLayer<AuthnProof, B>
where
    B: AuthnProofTransformer<AuthnProof>,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthnProof, B> Layer<S> for AuthnProofTransformerLayer<AuthnProof, B>
where
    B: AuthnProofTransformer<AuthnProof>,
{
    type Service = AuthnProofTransformerService<S, AuthnProof, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthnProofTransformerService::new(service, self.backend.clone())
    }
}
