use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;

use axum::{async_trait, response::IntoResponse, routing::get, Router};
use axum_authnz::authentication::backends::basic_auth::BasicAuthProof;
use axum_authnz::authentication::{AuthManagerLayer, AuthUser, User, UserWithRoles};
use axum_authnz::authorization::backends::role_authorization_backend::RoleAuthorizationBackend;
use axum_authnz::authorization::AuthorizationBuilder;
use axum_authnz::transform::backends::header_auth_proof_transformer::HeaderAuthProofTransformer;
use axum_authnz::{
    authentication::{AuthStateChange, AuthenticationBackend},
    transform::AuthProofTransformerLayer,
};
use tower::ServiceBuilder;

#[derive(Debug, Clone)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

impl User for MyUser {}

impl UserWithRoles for MyUser {
    fn roles(&self) -> HashSet<String> {
        self.roles.clone()
    }
}

#[async_trait]
impl AuthenticationBackend for DummyAuthenticationBackend {
    type AuthProof = BasicAuthProof;
    type Credentials = (); // Not used since we do not have login/logout as auth is stateless
    type Error = Infallible;
    type User = MyUser;

    // Logs in user
    //
    // Not used for this AuthenticationBackend since AuthProof=Credentials, there is no use for the login operation
    async fn login(
        &mut self,
        // ili requset: direkt
        _credentials: Self::Credentials,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        unimplemented!()
    }

    // Logs out user
    //
    // Not used for this AuthenticationBackend since AuthProof=Credentials, there is no use for the logout operation
    async fn logout(
        &mut self,
        _auth_proof: Self::AuthProof,
    ) -> Result<AuthStateChange<Self::AuthProof>, Self::Error> {
        unimplemented!()
    }

    // Checks if user is stored in local hashmap of users
    async fn authenticate(
        &mut self,
        auth_proof: Self::AuthProof,
    ) -> Result<AuthUser<Self::User>, Self::Error> {
        let result = self.users.get(&auth_proof).map_or_else(
            || Ok(AuthUser::Unaunthenticated),
            |user| Ok(AuthUser::Authenticated(user.clone())),
        );

        result
    }
}

#[derive(Debug, Clone)]
struct DummyAuthenticationBackend {
    pub users: HashMap<BasicAuthProof, MyUser>,
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
            .layer(auth_proof_transfomer_layer)
            .layer(authentication_layer)
            .layer(authorization_layer),
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
