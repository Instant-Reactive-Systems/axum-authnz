use axum::{async_trait, http::request::Parts};
use std::{convert::Infallible, marker::PhantomData};

use crate::{AuthzBackend, AuthnUser};

#[derive(Debug, Clone)]
pub struct LoginAuthzBackend<U> {
    _marker: PhantomData<U>,
}

impl<U> LoginAuthzBackend<U> {
    pub fn new() -> Self {
        LoginAuthzBackend {
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<U: std::fmt::Debug + Send + Sync + Clone + 'static> AuthzBackend<U> for LoginAuthzBackend<U> {
    type Error = Infallible;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let user = req_parts
            .extensions
            .get::<AuthnUser<U>>()
            .expect("Is AuthnLayer enabled?");

        match user {
            AuthnUser::Auth(_) => Ok(true),
            AuthnUser::Anon => Ok(false),
        }
    }
}
