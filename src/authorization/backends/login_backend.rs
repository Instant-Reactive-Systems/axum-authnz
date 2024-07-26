use std::{convert::Infallible, marker::PhantomData};

use axum::{async_trait, http::request::Parts};

use crate::{
    authentication::{AuthUser, User},
    authorization::AuthorizationBackend,
};

#[derive(Debug, Clone)]
pub struct LoginAuthorizationBackend<U: User + Send + Sync> {
    _marker: PhantomData<U>,
}

impl<U: User + Send + Sync> LoginAuthorizationBackend<U> {
    pub fn new() -> Self {
        LoginAuthorizationBackend {
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<U: User + Send + Sync + 'static> AuthorizationBackend<U> for LoginAuthorizationBackend<U> {
    type Error = Infallible;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let user = req_parts
            .extensions
            .get::<AuthUser<U>>()
            .expect("Is authentication layer enabled?");

        match user {
            AuthUser::Authenticated(_) => Ok(true),
            AuthUser::Unaunthenticated => Ok(false),
        }
    }
}
