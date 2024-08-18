use axum::{async_trait, response::IntoResponse, routing::get, Router};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
};
use tower::ServiceBuilder;

use axum_authnz::{
    authn::backends::basic_auth::BasicAuthnProof,
    authz::backends::role::{RoleAuthzBackend, UserWithRoles},
    transform::backends::header_authn_proof_transformer::HeaderAuthnProofTransformer,
    AuthnProofTransformerLayer, AuthnBackend, AuthnLayer, AuthnStateChange, AuthzBuilder, User,
};

#[derive(Debug, Clone)]
struct MyUser {
    id: u128,
    roles: HashSet<String>,
}

impl UserWithRoles for MyUser {
    fn roles(&self) -> HashSet<String> {
        self.roles.clone()
    }
}

#[async_trait]
impl AuthnBackend for BasicAuthnBackend {
    type AuthnProof = BasicAuthnProof;
    type Credentials = (); // Not used since we do not have login/logout as auth is stateless
    type Error = Infallible;
    type UserData = MyUser;

    // Logs in user
    //
    // Not used for this AuthenticationBackend since AuthnProof=Credentials, there is no use for the login operation
    async fn login(
        &mut self,
        // ili requset: direkt
        _credentials: Self::Credentials,
    ) -> Result<AuthnStateChange<Self::AuthnProof>, Self::Error> {
        unimplemented!()
    }

    // Logs out user
    //
    // Not used for this AuthenticationBackend since AuthnProof=Credentials, there is no use for the logout operation
    async fn logout(
        &mut self,
        _authn_proof: Self::AuthnProof,
    ) -> Result<AuthnStateChange<Self::AuthnProof>, Self::Error> {
        unimplemented!()
    }

    // Checks if user is stored in local hashmap of users
    async fn authenticate(
        &mut self,
        auth_proof: Self::AuthnProof,
    ) -> Result<User<Self::UserData>, Self::Error> {
        let result = self
            .users
            .get(&auth_proof)
            .map_or_else(|| Ok(User::Anon), |user| Ok(User::Auth(user.clone())));

        result
    }
}

#[derive(Debug, Clone)]
struct BasicAuthnBackend {
    pub users: HashMap<BasicAuthnProof, MyUser>,
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

#[tokio::main]
async fn main() {
    let mut users = HashMap::new();
    users.insert(
        BasicAuthnProof::new("username", "password"),
        MyUser {
            id: 0,
            roles: HashSet::from(["Einar".to_owned(), "Olaf".to_owned(), "Harald".to_owned()]),
        },
    );

    let auth_proof_transfomer_layer =
        AuthnProofTransformerLayer::<BasicAuthnProof, HeaderAuthnProofTransformer>::new(
            HeaderAuthnProofTransformer::new("Authorization".into()),
        );

    let authn_backend = BasicAuthnBackend { users };
    let authn_layer = AuthnLayer::new(authn_backend);

    let authz_layer = AuthzBuilder::new(RoleAuthzBackend::<MyUser>::new("Olaf"))
        .and(RoleAuthzBackend::new("Harald"))
        .or(RoleAuthzBackend::new("Einar"))
        .build();

    let app = Router::new().route("/", get(root)).route_layer(
        ServiceBuilder::new()
            .layer(auth_proof_transfomer_layer)
            .layer(authn_layer)
            .layer(authz_layer),
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
