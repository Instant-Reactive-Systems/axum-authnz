use axum::{
    async_trait,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tower_sessions::Session;

use crate::{AuthProofTransformer, AuthnStateChange};

#[derive(Debug, Clone)]
pub struct SessionAuthProofTransformer {
    auth_proof_key: String,
}

impl SessionAuthProofTransformer {
    /// Creates a new SessionAuthProofTransformer with the specified auth_proof_key.
    ///
    /// # Arguments
    /// * `auth_proof_key` - Cookie name which will be used for the authentication proof.
    pub fn new(auth_proof_key: impl Into<String>) -> Self {
        Self {
            auth_proof_key: auth_proof_key.into(),
        }
    }
}

#[async_trait]
impl<AuthProof> AuthProofTransformer<AuthProof> for SessionAuthProofTransformer
where
    AuthProof:
        Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> + DeserializeOwned + 'static,
{
    type Error = SessionAuthError;

    async fn insert_auth_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        let session = request.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(request),
        };

        if let Some(auth_proof) = session.get::<AuthProof>(&self.auth_proof_key).await? {
            request.extensions_mut().insert(auth_proof);
            Ok(request)
        } else {
            Ok(request)
        }
    }

    async fn process_auth_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error> {
        let session = response.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(response),
        };

        if let Some(auth_state_change) = response.extensions().get::<AuthnStateChange<AuthProof>>()
        {
            match auth_state_change {
                AuthnStateChange::LoggedIn(auth_proof) => {
                    session.cycle_id().await?;
                    session.insert(&self.auth_proof_key, auth_proof).await?;
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
pub enum SessionAuthError {
    #[error("Could not extract session manager from extensions")]
    MissingSesssionManagerLayer,
    #[error("Session error")]
    SessionError(#[from] tower_sessions::session::Error),
}

impl IntoResponse for SessionAuthError {
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
pub struct SessionAuthProofParseError(#[from] serde_json::Error);
