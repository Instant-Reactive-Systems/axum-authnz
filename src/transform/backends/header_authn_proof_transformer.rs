use axum::{async_trait, extract::Request, response::Response};
use std::convert::Infallible;

use crate::transform::AuthnProofTransformer;

/// A stateless [crate::transform::AuthnProofTransformer] implementation that extracts authentication
/// proof from a http header.
#[derive(Debug, Clone)]
pub struct HeaderAuthnProofTransformer {
    header: String,
}

impl HeaderAuthnProofTransformer {
    /// Creates a new instance of HeaderAuthnProofTransformer with the provided header used for
    /// authentication proof extraction.
    pub fn new(header: String) -> Self {
        Self { header }
    }
}

#[async_trait]
impl<AuthnProof> AuthnProofTransformer<AuthnProof> for HeaderAuthnProofTransformer
where
    AuthnProof: Clone + Send + Sync + TryFrom<Vec<u8>> + 'static,
{
    type Error = Infallible;

    async fn insert_authn_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        if let Some(header) = request.headers().get(&self.header) {
            let authn_proof: Result<AuthnProof, <AuthnProof as TryFrom<Vec<u8>>>::Error> =
                header.as_bytes().to_vec().try_into();

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

    async fn process_authn_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error> {
        // We do not process any auth state changes as this AuthnProofTransformer is stateless.
        Ok(response)
    }
}
