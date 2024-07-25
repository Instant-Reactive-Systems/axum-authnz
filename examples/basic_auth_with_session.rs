use std::collections::HashSet;
use std::convert::Infallible;
use std::{collections::HashMap, io::Read};

use axum::body::Bytes;
use axum::http::StatusCode;
use axum::Extension;
use axum::{
    async_trait,
    extract::Request,
    http::header,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use axum_authnz::authentication::{self, AuthManagerLayer, AuthUser, AuthenticationService, User};
use axum_authnz::authorization::backends::role_authorization_backend::RoleAuthorizationBackend;
use axum_authnz::authorization::{AuthorizationBuilder, AuthorizationLayer};
use axum_authnz::{
    authentication::{AuthProof, AuthStateChange, AuthenticationBackend},
    transform::{AuthProofTransformer, AuthProofTransformerLayer, AuthProofTransformerService},
};
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

type SessionAuthProof = MyUser;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct SessionAuthProofParseError(#[from] serde_json::Error);

impl AuthProof for SessionAuthProof {
    type Error = SessionAuthProofParseError;

    fn from_bytes(bytes: axum::body::Bytes) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct SessionAuthProofTransformer {
    auth_proof_key: String
}

impl SessionAuthProofTransformer {
    pub fn new(auth_proof_key: impl Into<String>) -> Self {
        Self {
            auth_proof_key: auth_proof_key.into()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

impl User for MyUser {
    fn roles(&self) -> HashSet<String> {
        self.roles.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BasicAuthCredentials {
    username: String,
    password: String,
}

impl BasicAuthCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        BasicAuthCredentials {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("invalid credentials")]
    InvalidCredentials,
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> Response {
        match self {
            AuthenticationError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
            }
        }
    }
}
#[async_trait]
impl AuthenticationBackend for DummyAuthenticationBackend {
    type AuthProof = SessionAuthProof;
    type Credentials = BasicAuthCredentials; // Not used since we do not have login/logout as auth is stateless
    type Error = AuthenticationError;
    type User = MyUser;

    /// Logs in user
    ///
    /// Should be called in login route handlers and returned in response to propagate changes to transform layer
    async fn login(
        &mut self,
        // ili requset: direkt
        credentials: Self::Credentials,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        let user = self
            .users
            .get(&credentials)
            .ok_or(AuthenticationError::InvalidCredentials)
            .map(|user| user.clone())?;

        Ok(AuthStateChange::LoggedIn(user))
    }

    /// Logs out user
    ///
    /// Should be called in logout route handlers and returned in response to propagate changes to transform layer.
    async fn logout(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        Ok(AuthStateChange::LoggedOut(auth_proof))
    }

    /// Verifies [crate::authentication::AuthProof] and returns the authenticated user
    async fn authenticate(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthUser<Self::User>, Self::Error> {
        Ok(AuthUser::Authenticated(auth_proof))
    }
}

#[derive(Debug, Clone)]
struct DummyAuthenticationBackend {
    pub users: HashMap<BasicAuthCredentials, MyUser>,
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
                "Can't extract session. Is `SessionManagerLayer` enabled?",
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
        let session = request
            .extensions()
            .get::<Session>()
            .cloned()
            .ok_or(SessionAuthError::MissingSesssionManagerLayer)?;

        if let Some(auth_proof) = session.get::<AuthnProof>(&self.auth_proof_key).await? {
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
        Ok(response)
    }
}

async fn root(user: AuthUser<MyUser>) -> impl IntoResponse {
    match user {
        AuthUser::Authenticated(user) => {
            format!("Hello user: {}", user.id)
        }
        AuthUser::Unaunthenticated => {
            format!("Hello anonymous one")
        }
    }
}

#[tokio::main]
async fn main() {
    let mut users = HashMap::new();
    users.insert(
        BasicAuthCredentials::new("username", "password"),
        MyUser {
            id: 0,
            roles: HashSet::from(["Einar".to_owned(), "Olaf".to_owned(), "Harald".to_owned()]),
        },
    );

    let session_store = MemoryStore::default();
    let session_layer =
        SessionManagerLayer::new(session_store).with_expiry(tower_sessions::Expiry::OnSessionEnd);

    let auth_proof_transfomer_layer =
        AuthProofTransformerLayer::<SessionAuthProof, SessionAuthProofTransformer>::new(
            SessionAuthProofTransformer::new("auth_proof"),
        );

    let authentication_backend = DummyAuthenticationBackend { users };
    let authentication_layer = AuthManagerLayer::new(authentication_backend);

    let authorization_layer =
        AuthorizationBuilder::new(RoleAuthorizationBackend::<MyUser>::new("Olaf"))
            .and(RoleAuthorizationBackend::new("Harald"))
            .or(RoleAuthorizationBackend::new("Einar"))
            .build();

    let app = Router::new().route("/", get(root)).route_layer(
        ServiceBuilder::new()
            .layer(session_layer)
            .layer(auth_proof_transfomer_layer)
            .layer(authentication_layer)
            .layer(authorization_layer),
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
