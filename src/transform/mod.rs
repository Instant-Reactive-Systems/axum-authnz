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

use crate::authentication::AuthProof;

pub mod backends;

/// Extracts and inserts (transforms) [crate::authentication::AuthProof] from requests/responses
///
/// Used as a layer to transform different types of client side provided data along with any state into [crate::authentication::AuthProof]
///
/// It is up to the implementor of [crate::authentication::AuthProof] to handle converting raw parsed bytes into and from itself
///
/// For example:
///     - HeaderAuthProofTransformer extracts [crate::authentication::AuthProof] from the request header using no state, ignores login/logout event,
///       useful for services that only do authorization with no login/logout flows
///     - CookieAuthProofTransformer extracts [crate::authentication::AuthProof] from regular, private and signed cookies using no state
///       and sets/unsets the cookies upon login/logout events
///     - SessionAuthProofTransformer extracts [crate::authentication::AuthProof] from http sessions using tower sessions
///       
/// and creates/destroys the session upon login/logout requests
#[async_trait]
pub trait AuthProofTransformer<T: AuthProof>: std::fmt::Debug + Clone + Send + Sync {
    type Error: Send + Sync + IntoResponse;

    /// Inserts [crate::authentication::AuthProof] into the request and returns the modified request with [crate::authentication::AuthProof]
    /// inserted into extensions
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_auth_proof(&mut self, request: Request) -> Result<Request, Self::Error>;

    /// Receives and handles [crate::authentication::AuthStateChange] in response extensions
    ///
    /// For example for session based auth and the LoggedIn event we would insert a new session and return the modified response which contains the session id
    /// [crate::authentication::AuthProof] into it so we can identify the user on new requests
    async fn process_auth_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct AuthProofTransformerService<S, AuthnProof, Backend>
where
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof>,
{
    inner: S,
    backend: Backend,
    _marker: PhantomData<AuthnProof>,
}

impl<S, AuthnProof, Backend> AuthProofTransformerService<S, AuthnProof, Backend>
where
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof>,
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
impl<S, Backend, AuthnProof> Service<Request>
    for AuthProofTransformerService<S, AuthnProof, Backend>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof> + 'static,
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
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof>,
{
    backend: Backend,
    _marker: PhantomData<AuthnProof>,
}

impl<AuthnProof, Backend> AuthSessionLayer<AuthnProof, Backend>
where
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof>,
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
    AuthnProof: AuthProof,
    Backend: AuthProofTransformer<AuthnProof>,
{
    type Service = AuthProofTransformerService<S, AuthnProof, Backend>;

    fn layer(&self, service: S) -> Self::Service {
        AuthProofTransformerService::new(service, self.backend.clone())
    }
}
