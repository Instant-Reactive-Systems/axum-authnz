use axum::{
    async_trait,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tower::ServiceBuilder;
use tower_sessions::{cookie::time::Duration, MemoryStore, Session, SessionManagerLayer};

use axum_authnz::{
    authn::backends::basic_auth::{BasicAuthCredentials, BasicAuthnProof},
    authz::backends::{
        login::LoginAuthzBackend,
        role::{RoleAuthzBackend, UserWithRoles},
    },
    transform::backends::session_authn_proof_transformer::SessionAuthnProofTransformer,
    AuthnProofTransformerLayer, Authn, AuthnBackend, AuthnLayer, AuthnStateChange, AuthzBuilder,
    User,
};

type SessionAuthnProof = MyUser;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

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
impl AuthnBackend for DummyAuthenticationBackend {
    type AuthnProof = SessionAuthnProof;
    type Credentials = BasicAuthCredentials; // Not used since we do not have login/logout as auth is stateless
    type Error = AuthenticationError;
    type UserData = MyUser;

    /// Logs in user
    ///
    /// Should be called in login route handlers and returned in response to propagate changes to transform layer
    async fn login(
        &mut self,
        // ili requset: direkt
        credentials: Self::Credentials,
    ) -> Result<AuthnStateChange<Self::AuthnProof>, Self::Error> {
        let user = self
            .users
            .get(&credentials)
            .ok_or(AuthenticationError::InvalidCredentials)
            .map(|user| user.clone())?;

        Ok(AuthnStateChange::LoggedIn(user))
    }

    /// Logs out user
    ///
    /// Should be called in logout route handlers and returned in response to propagate changes to transform layer.
    async fn logout(
        &mut self,
        authn_proof: Self::AuthnProof,
    ) -> Result<AuthnStateChange<Self::AuthnProof>, Self::Error> {
        Ok(AuthnStateChange::LoggedOut(authn_proof))
    }

    /// Verifies [crate::authentication::AuthnProof] and returns the authenticated user
    async fn authenticate(
        &mut self,
        authn_proof: Self::AuthnProof,
    ) -> Result<User<Self::UserData>, Self::Error> {
        // verifies the auth proof here...
        Ok(User::Auth(authn_proof))
    }
}

#[derive(Debug, Clone)]
struct DummyAuthenticationBackend {
    pub users: HashMap<BasicAuthCredentials, MyUser>,
}

async fn root(user: User<MyUser>) -> impl IntoResponse {
    match user {
        User::Auth(user) => {
            format!("Hello user: {}", user.id)
        }
        User::Anon => {
            format!("Hello anonymous one")
        }
    }
}

async fn login(
    mut authn: Authn<DummyAuthenticationBackend>,
    credentials: Form<BasicAuthCredentials>,
) -> Response {
    let login_result = authn.login(credentials.0).await;

    match login_result {
        Ok(auth_state_change) => (auth_state_change, Redirect::to("/")).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn logout(
    mut authn: Authn<DummyAuthenticationBackend>,
    authn_proof: Option<Extension<SessionAuthnProof>>,
) -> impl IntoResponse {
    if let Some(authn_proof) = authn_proof {
        let logout_result = authn.logout(authn_proof.0).await;

        match logout_result {
            Ok(authn_state_change) => (authn_state_change, Redirect::to("/login")).into_response(),
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

    let authn_proof_transfomer_layer = AuthnProofTransformerLayer::<
        SessionAuthnProof,
        SessionAuthnProofTransformer,
    >::new(SessionAuthnProofTransformer::new("authn_proof"));

    let authn_backend = DummyAuthenticationBackend { users };
    let authn_layer = AuthnLayer::new(authn_backend);

    let authz_layer = AuthzBuilder::new(LoginAuthzBackend::<MyUser>::new()).build();

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
        .route("/logout", post(logout).layer(authz_layer))
        .route("/", get(root))
        .route_layer(
            ServiceBuilder::new()
                .layer(session_layer)
                .layer(authn_proof_transfomer_layer)
                .layer(authn_layer)
                .layer(middleware::from_fn(propagate_session_to_response)),
        );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
