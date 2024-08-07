use axum::{async_trait, extract::Request, response::Response};
use std::convert::Infallible;

use crate::AuthProofTransformer;

/// A stateless [crate::transform::AuthProofTransformer] implementation that extracts authentication
/// proof from a http header.
#[derive(Debug, Clone)]
pub struct HeaderAuthProofTransformer {
    header: String,
}

impl HeaderAuthProofTransformer {
    /// Creates a new instance of HeaderAuthProofTransformer with the provided header used for
    /// authentication proof extraction.
    pub fn new(header: String) -> Self {
        Self { header }
    }
}

#[async_trait]
impl<AuthProof> AuthProofTransformer<AuthProof> for HeaderAuthProofTransformer
where
    AuthProof: Clone + Send + Sync + TryFrom<Vec<u8>> + 'static,
{
    type Error = Infallible;

    async fn insert_auth_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        if let Some(header) = request.headers().get(&self.header) {
            let auth_proof: Result<AuthProof, <AuthProof as TryFrom<Vec<u8>>>::Error> =
                header.as_bytes().to_vec().try_into();

            match auth_proof {
                Ok(auth_proof) => {
                    request.extensions_mut().insert(auth_proof);
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

    async fn process_auth_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error> {
        // We do not process any auth state changes as this AuthProofTransformer is stateless.
        Ok(response)
    }
}
