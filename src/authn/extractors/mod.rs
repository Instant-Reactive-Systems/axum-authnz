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

/// Extracts and inserts an authentication proof
///
/// Used as a layer to transform different types of client-side provided data into
/// an authentication proof.s.
#[async_trait]
pub trait AuthnProofExtractor<AuthnProof>: std::fmt::Debug + Clone + Send + Sync + 'static {
    type Error: Send + Sync + IntoResponse;

    /// Inserts an authentication proof into the request and returns the modified request
    /// with the authentication proof inserted into the request extensions.
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_authn_proof(&mut self, request: Request) -> Result<Request, Self::Error>;

}

/// A request extension that exposes a way to interact with the [`AuthnProofExtractor`].
#[derive(Debug, Clone)]
pub struct AuthnProofExtractorService<S, AuthnProof, B>
where
    B: AuthnProofExtractor<AuthnProof>,
{
    inner: S,
    backend: B,
    _marker: PhantomData<AuthnProof>,
}

impl<S, AuthnProof, B> AuthnProofExtractorService<S, AuthnProof, B>
where
    B: AuthnProofExtractor<AuthnProof>,
{
    pub fn new(inner: S, backend: B) -> Self {
        Self {
            inner,
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthnProof, B> Service<Request> for AuthnProofExtractorService<S, AuthnProof, B>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: AuthnProofExtractor<AuthnProof> + 'static,
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


            Ok(resp)
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthnProofExtractorLayer<AuthnProof, B>
where
    B: AuthnProofExtractor<AuthnProof>,
{
    backend: B,
    _marker: PhantomData<AuthnProof>,
}

impl<AuthnProof, B> AuthnProofExtractorLayer<AuthnProof, B>
where
    B: AuthnProofExtractor<AuthnProof>,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            _marker: PhantomData,
        }
    }
}

impl<S, AuthnProof, B> Layer<S> for AuthnProofExtractorLayer<AuthnProof, B>
where
    B: AuthnProofExtractor<AuthnProof>,
{
    type Service = AuthnProofExtractorService<S, AuthnProof, B>;

    fn layer(&self, service: S) -> Self::Service {
        AuthnProofExtractorService::new(service, self.backend.clone())
    }
}