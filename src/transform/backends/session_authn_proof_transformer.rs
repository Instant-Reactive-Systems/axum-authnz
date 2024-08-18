use axum::{
    async_trait,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tower_sessions::Session;

use crate::authn::AuthnStateChange;
use crate::transform::AuthnProofTransformer;

#[derive(Debug, Clone)]
pub struct SessionAuthnProofTransformer {
    authn_proof_key: String,
}

impl SessionAuthnProofTransformer {
    /// Creates a new SessionAuthnProofTransformer with the specified authn_proof_key.
    ///
    /// # Arguments
    /// * `authn_proof_key` - Cookie name which will be used for the authentication proof.
    pub fn new(authn_proof_key: impl Into<String>) -> Self {
        Self {
            authn_proof_key: authn_proof_key.into(),
        }
    }
}

#[async_trait]
impl<AuthnProof> AuthnProofTransformer<AuthnProof> for SessionAuthnProofTransformer
where
    AuthnProof:
        Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + DeserializeOwned + 'static,
{
    type Error = SessionAuthnError;

    async fn insert_authn_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        let session = request.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(request),
        };

        if let Some(authn_proof) = session.get::<AuthnProof>(&self.authn_proof_key).await? {
            request.extensions_mut().insert(authn_proof);
            Ok(request)
        } else {
            Ok(request)
        }
    }

    async fn process_authn_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error> {
        let session = response.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(response),
        };

        if let Some(authn_state_change) = response.extensions().get::<AuthnStateChange<AuthnProof>>()
        {
            match authn_state_change {
                AuthnStateChange::LoggedIn(authn_proof) => {
                    session.cycle_id().await?;
                    session.insert(&self.authn_proof_key, authn_proof).await?;
                }
                AuthnStateChange::LoggedOut(_) => {
                    session.flush().await?;
                }
            }
        }

        Ok(response)
    }
}

#[derive(Debug, Error)]
pub enum SessionAuthnError {
    #[error("Could not extract session manager from extensions")]
    MissingSesssionManagerLayer,
    #[error("Session error")]
    SessionError(#[from] tower_sessions::session::Error),
}

impl IntoResponse for SessionAuthnError {
    fn into_response(self) -> Response {
        match self {
            Self::MissingSesssionManagerLayer => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Is SessionManagerLayer enabled?",
            )
                .into_response(),
            Self::SessionError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal session manager error",
            )
                .into_response(),
        }
    }
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct SessionAuthnProofParseError(#[from] serde_json::Error);
