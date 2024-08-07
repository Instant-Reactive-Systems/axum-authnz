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
///     - HeaderAuthProofTransformer extracts an authentication proof
///       from the request header using no state, ignores login/logout event,
///       useful for services that only do authentication with no login/logout flows.
///     - SessionAuthProofTransformer extracts an authentication proof from http sessions
///       using tower sessions and creates/destroys the session upon login/logout requests.
#[async_trait]
pub trait AuthProofTransformer<AuthProof>: std::fmt::Debug + Clone + Send + Sync + 'static {
    type Error: Send + Sync + IntoResponse;

    /// Inserts an authentication proof into the request and returns the modified request
    /// with the authentication proof inserted into the request extensions.
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_auth_proof(&mut self, request: Request) -> Result<Request, Self::Error>;

    /// Receives and handles an [`crate::authn::AuthStateChange`] from the response extensions.
    ///
    /// For example, for session based auth and the LoggedIn event,
    /// we would insert a new session and return the modified response
    /// which contains the session id.
    async fn process_auth_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error>;
}

/// A request extension that exposes a way to interact with the [`AuthProofTransformer`].
#[derive(Debug, Clone)]
pub struct AuthProofTransformerService<S, AuthProof, B>
where
    B: AuthProofTransformer<AuthProof>,
{
    inner: S,
    backend: B,
    _marker: PhantomData<AuthProof>,
}

impl<S, AuthProof, B> AuthProofTransformerService<S, AuthProof, B>
where
    B: AuthProofTransformer<AuthProof>,
{
    pub fn new(inner: S, backend: B) -> Self {
        Self {
            inner,
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthProof, B> Service<Request> for AuthProofTransformerService<S, AuthProof, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: AuthProofTransformer<AuthProof> + 'static,
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
            let req = match backend.insert_auth_proof(req).await {
                Ok(req) => req,
                Err(err) => return Ok(err.into_response()),
            };

            let resp = inner.call(req).await?;

            let resp = match backend.process_auth_state_change(resp).await {
                Ok(resp) => resp,
                Err(err) => return Ok(err.into_response()),
            };

            Ok(resp)
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthProofTransformerLayer<AuthProof, B>
where
    B: AuthProofTransformer<AuthProof>,
{
    backend: B,
    _marker: PhantomData<AuthProof>,
}

impl<AuthProof, B> AuthProofTransformerLayer<AuthProof, B>
where
    B: AuthProofTransformer<AuthProof>,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthProof, B> Layer<S> for AuthProofTransformerLayer<AuthProof, B>
where
    B: AuthProofTransformer<AuthProof>,
{
    type Service = AuthProofTransformerService<S, AuthProof, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthProofTransformerService::new(service, self.backend.clone())
    }
}
