use axum::{async_trait, extract::Request, http::HeaderValue};
use std::convert::Infallible;

use crate::authn::extractors::AuthnProofExtractor;

/// A stateless [crate::transform::AuthnProofExtractor] implementation that extracts authentication
/// proof from a http header.
#[derive(Debug, Clone)]
pub struct HeaderAuthnProofExtractor {
    header_key: String,
}

impl HeaderAuthnProofExtractor {
    /// Creates a new instance of HeaderAuthnProofExtractor with the provided header used for
    /// authentication proof extraction.
    pub fn new(header_key: String) -> Self {
        Self { header_key }
    }
}

#[async_trait]
impl<AuthnProof> AuthnProofExtractor<AuthnProof> for HeaderAuthnProofExtractor
where
    AuthnProof: Clone + Send + Sync + TryFrom<HeaderValue> + 'static,
{
    type Error = Infallible;

    async fn insert_authn_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        if let Some(header) = request.headers().get(&self.header_key) {
            let authn_proof: Result<AuthnProof, <AuthnProof as TryFrom<HeaderValue>>::Error> = header.clone().try_into();

            match authn_proof {
                Ok(authn_proof) => {
                    request.extensions_mut().insert(authn_proof);
                    Ok(request)
                }
                Err(_err) => {
                    // TODO: Log errors or maybe deny request with it being instead to fail early
                    // Lets decide together what the best semantics should be, i believe we should
                    // fail with malformed request
                    Ok(request)
                }
            }
        } else {
            Ok(request)
        }
    }

}