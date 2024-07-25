use std::collections::HashSet;
use std::convert::Infallible;
use std::{collections::HashMap, io::Read};

use axum::body::Bytes;
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
use serde::Serialize;
use thiserror::Error;
use tower::ServiceBuilder;
use tower_sessions::{MemoryStore, SessionManagerLayer};

type SessionAuthProof = MyUser;

#[derive(Error, Debug)]
#[error(transparent)]
pub struct SessionAuthProofParseError(#[from] serde_json::Error);

impl AuthProof for SessionAuthProof {
    type Error = SessionAuthProofParseError;

    fn from_bytes(bytes: axum::body::Bytes) -> Result<Self, Self::Error> {}
}

#[derive(Debug, Clone)]
pub struct SessionAuthProofTransformer {}

impl SessionAuthProofTransformer {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

impl User for MyUser {
    fn roles(&self) -> HashSet<String> {
        self.roles.clone()
    }
}

#[async_trait]
impl AuthenticationBackend for DummyAuthenticationBackend {
    type AuthProof = SessionAuthProof;
    type Credentials = (); // Not used since we do not have login/logout as auth is stateless
    type Error = Infallible;
    type User = MyUser;

    /// Logs in user
    ///
    /// Should be called in login route handlers and returned in response to propagate changes to transform layer
    async fn login(
        &mut self,
        // ili requset: direkt
        _credentials: Self::Credentials,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        unimplemented!()
    }

    /// Logs out user
    ///
    /// Should be called in logout route handlers and returned in response to propagate changes to transform layer.
    async fn logout(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        unimplemented!()
    }

    /// Verifies [crate::authentication::AuthProof] and returns the authenticated user
    async fn authenticate(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthUser<Self::User>, Self::Error> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
struct DummyAuthenticationBackend {
    pub users: HashMap<BasicAuthProof, MyUser>,
}

#[async_trait]
impl<AuthnProof: AuthProof + 'static> AuthProofTransformer<AuthnProof>
    for HeaderAuthProofTransformer
{
    type Error = Infallible;

    /// Inserts [crate::authentication::AuthProof] into the request and returns the modified request with [crate::authentication::AuthProof]
    /// inserted into extensions
    ///
    /// Refer to [https://github.com/tokio-rs/axum/blob/main/examples/consume-body-in-extractor-or-middleware/src/main.rs]
    async fn insert_auth_proof(&mut self, mut request: Request) -> Result<Request, Self::Error> {
        if let Some(header) = request.headers().get(&self.header) {
            let auth_proof = AuthnProof::from_bytes(Bytes::copy_from_slice(header.as_bytes()));
            match auth_proof {
                Ok(auth_proof) => {
                    println!("{:?}", auth_proof);
                    request.extensions_mut().insert(auth_proof);
                    Ok(request)
                }
                Err(err) => {
                    println!("{:?}", err);
                    Ok(request)
                }
            }
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
        BasicAuthProof::new("username", "password"),
        MyUser {
            id: 0,
            roles: HashSet::from(["Einar".to_owned(), "Olaf".to_owned(), "Harald".to_owned()]),
        },
    );

    let session_store = MemoryStore::default();
    let session_layer =
        SessionManagerLayer::new(session_store).with_expiry(tower_sessions::Expiry::OnSessionEnd);

    let auth_proof_transfomer_layer =
        AuthProofTransformerLayer::<BasicAuthProof, HeaderAuthProofTransformer>::new(
            HeaderAuthProofTransformer::new("Authorization".into()),
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
