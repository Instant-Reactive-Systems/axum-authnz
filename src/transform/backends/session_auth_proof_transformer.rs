use axum::{
    async_trait,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tower_sessions::Session;

use crate::{
    authentication::{AuthProof, AuthStateChange},
    transform::AuthProofTransformer,
};

#[derive(Debug, Clone)]
pub struct SessionAuthProofTransformer {
    auth_proof_key: String,
}

impl SessionAuthProofTransformer {
    /// Creates a new SessionAuthProofTransformer with the specified auth_proof_key
    /// # Arguments
    ///
    /// * `auth_proof_key` - Cookie name which will be used for the authentication proof
    pub fn new(auth_proof_key: impl Into<String>) -> Self {
        Self {
            auth_proof_key: auth_proof_key.into(),
        }
    }
}

#[async_trait]
impl<
        AuthnProof: AuthProof + 'static + Serialize + for<'de> Deserialize<'de> + DeserializeOwned,
    > AuthProofTransformer<AuthnProof> for SessionAuthProofTransformer
{
    type Error = SessionAuthError;

    /// Inserts [crate::authentication::AuthProof] into the request and returns the modified request with [crate::authentication::AuthProof]
    /// inserted into extensions
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_auth_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        let session = request.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(request),
        };

        if let Some(auth_proof) = session.get::<AuthnProof>(&self.auth_proof_key).await? {
            println!("Got auth proof");
            request.extensions_mut().insert(auth_proof);
            Ok(request)
        } else {
            Ok(request)
        }
    }

    /// Receives and handles [crate::authentication::AuthStateChange] in response extensions
    ///
    /// For example for session based auth and the LoggedIn event we would insert a new session and return the modified response which contains the session id
    /// [crate::authentication::AuthProof] into it so we can identify the user on new requests
    async fn process_auth_state_change(
        &mut self,
        response: Response,
    ) -> Result<Response, Self::Error> {
        let session = response.extensions().get::<Session>().cloned(); // TODO: Or just use seflf, check which is better, also check clones and possible optimizations everywhere

        let session = match session {
            Some(session) => session,
            None => return Ok(response),
        };

        if let Some(auth_state_change) = response.extensions().get::<AuthStateChange<AuthnProof>>()
        {
            match auth_state_change {
                AuthStateChange::LoggedIn(auth_proof) => {
                    session.cycle_id().await?;
                    session.insert(&self.auth_proof_key, auth_proof).await?;
                }
                AuthStateChange::LoggedOut(_) => {
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
                "Is 'SessionManagerLayer` enabled?",
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
