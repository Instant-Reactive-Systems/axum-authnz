/*
use axum::{async_trait, extract::Request, response::Response, routing::get, Router};
use axum_authnz::{AuthSessionBackend, AuthSessionLayer, AuthStateChange, AuthenticationProof};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;

struct User {
    username: String,
    password: String,
    fullname: String,
}

#[derive(Debug, Clone)]
struct BasicAuthenticationProof {
    username: String,
    password: String,
}

impl TryFrom<String> for BasicAuthenticationProof {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let split = value.split_once(' ');
        match split {
            Some((name, contents)) if name == "Basic" => {
                let decoded: Vec<u8> = base64::engine::general_purpose::STANDARD
                    .decode(contents)
                    .map_err(|_| ())?;

                let decoded = String::from_utf8(decoded).map_err(|_| ())?;

                // Return depending on if password is present
                if let Some((id, password)) = decoded.split_once(':') {
                    Ok(BasicAuthenticationProof {
                        username: id.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    Err(())
                }
            }
            _ => Err(()),
        }
    }
}

impl axum_authnz::AuthenticationProof for BasicAuthenticationProof {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.username.clone()
    }
}

#[derive(Debug, Clone)]
pub struct BasicAuthSessionBackend;


#[async_trait]
impl<AuthnProof: AuthenticationProof + 'static> axum_authnz::AuthSessionBackend<AuthnProof>
    for BasicAuthSessionBackend
{
    type Error = ();

    async fn extract_authentication_proof(
        &mut self,
        mut request: Request,
    ) -> Result<Request, Self::Error> {
        let authorization_header = request.headers().get("Authorization");

        match authorization_header {
            Some(authorization_header) => {
                println!("{:?}", authorization_header);
                let authentication_proof =
                    AuthnProof::try_from(authorization_header.to_str().unwrap().to_owned())
                        .map_err(|_| anyhow::anyhow!("Die niggers"))
                        .unwrap();

                println!("{:?}", authentication_proof);
                request.extensions_mut().insert(authentication_proof);
            }
            None => (),
        }
        Ok(request)
    }

    async fn extract_authentication_proof2(
        &mut self,
        mut request: Request,
    ) -> Result<Request, Self::Error> {
        // Stateless -> ovdje je dost jedan
        // Statefull -> ovdje je dost jedan
        //   - session_id : keycloak (ID/ACCESS TOKEN)
        //   - session_id : pgsql (uid)
        //   - session_id : authelia (username)
        // req.extension.insert(authentication_proof)
        struct AuthenticationProof {
            keycloak_id: String,
            claims: String,
        }

        type User = AuthenticationProof;

        let session_manager = self.session_manager;

        let session_id = request.cookies.get("session_id").unwrap();
        let authentication_proof = session_manager.get(session_id);
        if let Some(authentication_proof) = authentication_proof {
            request.extensions_mut().insert(authentication_proof)
        }

        AuthenticationProof = User;

        request
    }

    async fn process_auth_state_change(
        &mut self,
        mut response: Response,
    ) -> Result<Response, Self::Error> {
        Ok(response)
    }
}

#[tokio::main]
async fn main() {
    let auth_session_backend = BasicAuthSessionBackend;

    // build our application with a single route
    let app = Router::new()
        // ovaj layer je applyan ne sve routeove, al ne pruza nikakav protection nego samo extraction Usera
        .layer(ServiceBuilder::new().layer(AuthSessionLayer::<
            IRSAuthenticationProof,
            CookieAuthSessionBackend>::new(auth_session_backend)
            )
            .layer(IRSAuthenticationLayer)
        )
        .route("/", get(|| async { "Hello, World!" }))
        .route("/protected_route", get(|| async { "Protected"})).layer(AuthorizationLayer::new().login_required().predicate(|user, authorization_backend| some_bool).has_permission("permission").unauthorized_response(redirect))
        .route("/unprotected_route", get(|user: Option<User>, authorzation_service: AuthoriationService| {
            if user.is_none() || !user.unwrap().has_permission("read:books"){
                return 401
            } else {
                 // read books
            }
        })
         // insert user if valid

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}


req -> AuthSessionService -> calls AuthSessionBackend.extract_authentication_proof(req) -> inserts extension AuthenticationProof into request -> call request -> AuthenticationService -> calls AuthenticationBackend -> checks validity of AuthenticationProof -> inserts User -> calls AuthorizationService -> calls AuthorizationBackend -> allows or denies request based on user permissions



// Flow za protected routeove, pretpostavljamo da user postoji
1. req
2. AuthSessionService
3. AuthSessionService.backend.extract_authentication_proof() -> AuthenticationProof u request extensionioma
4. AuthenicationService
5. AuthenticationService.backend.authenticate() -> User u request extensionioma
6. AuthorizationService
7. AuthorizationService.backend.has_permission("/neki_resource", req.extensions.get(User))
8. Finalni handler

// Flow za /login route
1. req
2. AuthSessionService
3. AuthSessionService.backend.extract_authentication_proof() -> AuthenticationProof u request extensionioma
    - ovdje ce ti vratit malformed reuqest ako je invalid header
4. AuthenticationService
5. AuthenticationService.backend.authenticate() -> User u request extensionioma
    - ako nema authenticationproofa nikom nista idemo dalje
    - ako je user authenticated -> inserta User u extension
    - ako nije ne inserta
    - u praksi jedino sta bi trebalo bit od errora je Internal Server Error ak negdje pukne u extractanju usera
6. Finalni handler /login
    pub fn handler(credentials: Credentials, user: Option<User>, auth_service: AuthenticationService) -> {
        if user.is_some() {
            return redirect("/home");
        }

        let login_result = auth_service.login();

        if login_result.success() {
            login_result.extension.get_value(), redirect(204)
        } else {
            500
        }

    }
7. AuthenticationService -> nista
8. AuthSessionService -> checkat jel u extensioima ima authstatechange, i ako da insertat novi auth proof
     - pure basic auth uopce nema login jer nema smisla jer je authentication_proof = credentiasima
     - session auth dobije kao authentication neki user id i setta session cookie i spremi u bazu
     - jwt auth dobije jwt token token i setta ga u headeru
     - keycloak cookie auth dobije keycloak id/access token i setta ga u private signed cookiejima


*/

use std::collections::HashSet;
use std::convert::Infallible;
use std::{collections::HashMap, io::Read};

use axum::body::Bytes;
use axum::http::request;
use axum::middleware::Next;
use axum::{
    async_trait,
    extract::Request,
    http::header,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use axum::{middleware, Extension};
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
use tower_sessions::Session;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BasicAuthProof {
    username: String,
    password: String,
}

impl BasicAuthProof {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        BasicAuthProof {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum BasicAuthProofParseError {
    #[error("invalid authentication type")]
    InvalidAuthenticationType,
    #[error("invalid authentication value")]
    InvalidAuthenticationValue,
    #[error("missing passsword")]
    MissingPassword,
    #[error("invalid header encoding")]
    InvalidHeaderEncoding, // Do we need this?
}

impl AuthProof for BasicAuthProof {
    type Error = BasicAuthProofParseError;

    fn from_bytes(bytes: axum::body::Bytes) -> Result<Self, Self::Error> {
        let header_value: String = String::from_utf8(bytes.to_vec())
            .map_err(|_| BasicAuthProofParseError::InvalidHeaderEncoding)?;

        let split = header_value.split_once(' ');

        match split {
            Some((name, contents)) if name == "Basic" => {
                let decoded: Vec<u8> =
                    base64::engine::general_purpose::STANDARD
                        .decode(contents)
                        .map_err(|_| BasicAuthProofParseError::InvalidAuthenticationValue)?;

                let decoded = String::from_utf8(decoded)
                    .map_err(|_| BasicAuthProofParseError::InvalidAuthenticationValue)?;

                // Return depending on if password is present
                if let Some((id, password)) = decoded.split_once(':') {
                    Ok(BasicAuthProof {
                        username: id.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    Err(BasicAuthProofParseError::MissingPassword)
                }
            }
            _ => Err(BasicAuthProofParseError::InvalidAuthenticationType),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HeaderAuthProofTransformer {
    header: String,
}

impl HeaderAuthProofTransformer {
    pub fn new(header: String) -> Self {
        Self { header }
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
    type AuthProof = BasicAuthProof;
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
        let result = self.users.get(&auth_proof).map_or_else(
            || Ok(AuthUser::Unaunthenticated),
            |user| Ok(AuthUser::Authenticated(user.clone())),
        );

        println!("result");
        result
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
            .layer(authorization_layer)
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
