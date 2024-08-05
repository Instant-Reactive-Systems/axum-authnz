use std::collections::HashMap;
use std::collections::HashSet;

use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Redirect;
use axum::routing::post;
use axum::{
    async_trait,
    extract::Request,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum::{middleware, Extension, Form};
use axum_authnz::authentication::backends::basic_auth::BasicAuthCredentials;
use axum_authnz::authentication::{
    AuthManagerLayer, AuthUser, AuthenticationService, User, UserWithRoles,
};
use axum_authnz::authorization::backends::login_backend::LoginAuthorizationBackend;
use axum_authnz::authorization::AuthorizationBuilder;
use axum_authnz::transform::backends::session_auth_proof_transformer::SessionAuthProofTransformer;
use axum_authnz::{
    authentication::{AuthProof, AuthStateChange, AuthenticationBackend},
    transform::AuthProofTransformerLayer,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_sessions::cookie::time::Duration;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

type SessionAuthProof = MyUser;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

impl User for MyUser {}
impl AuthProof for MyUser {}

impl UserWithRoles for MyUser {
    fn roles(&self) -> HashSet<String> {
        self.roles.clone()
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

async fn login(
    mut authentication_service: AuthenticationService<DummyAuthenticationBackend>,
    credentials: Form<BasicAuthCredentials>,
) -> Response {
    let login_result = authentication_service.login(credentials.0).await;

    match login_result {
        Ok(auth_state_change) => (auth_state_change, Redirect::to("/")).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn logout(
    mut authentication_service: AuthenticationService<DummyAuthenticationBackend>,
    auth_proof: Option<Extension<SessionAuthProof>>,
) -> impl IntoResponse {
    if let Some(auth_proof) = auth_proof {
        let logout_result = authentication_service.logout(auth_proof.0).await;

        match logout_result {
            Ok(auth_state_change) => (auth_state_change, Redirect::to("/login")).into_response(),
            Err(e) => e.into_response(),
        }
    } else {
        Redirect::to("/").into_response()
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
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(tower_sessions::Expiry::OnInactivity(Duration::hours(5)));

    let auth_proof_transfomer_layer = AuthProofTransformerLayer::<
        SessionAuthProof,
        SessionAuthProofTransformer,
    >::new(SessionAuthProofTransformer::new("auth_proof"));

    let authentication_backend = DummyAuthenticationBackend { users };
    let authentication_layer = AuthManagerLayer::new(authentication_backend);

    let authorization_layer =
        AuthorizationBuilder::new(LoginAuthorizationBackend::<MyUser>::new()).build();

    async fn propagate_session_to_response(req: Request, next: Next) -> Response {
        let session = req.extensions().get::<Session>().cloned();
        let mut response = next.run(req).await;

        if let Some(session) = session {
            println!("Inserting session");
            println!("{:?}", session);
            session.insert("TEST", 5).await.unwrap();
            response.extensions_mut().insert(session);
        } else {
            println!("No session")
        }

        response
    }

    let app = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout).layer(authorization_layer))
        .route("/", get(root))
        .route_layer(
            ServiceBuilder::new()
                .layer(session_layer)
                .layer(auth_proof_transfomer_layer)
                .layer(authentication_layer)
                .layer(middleware::from_fn(propagate_session_to_response)),
        );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
