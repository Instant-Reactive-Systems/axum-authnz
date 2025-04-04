use axum::{async_trait, http::request::Parts};
use std::{convert::Infallible, marker::PhantomData};

use crate::{authn::User, AuthnUser, AuthzBackend};

#[derive(Debug, Clone)]
pub struct LoginAuthzBackend<U> {
    _marker: PhantomData<U>,
}

impl<U> Default for LoginAuthzBackend<U> {
    fn default() -> Self {
        Self::new()
    }
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
            .get::<User<U>>()
            .expect("Is AuthnLayer enabled?");

        match user {
            User::Authn(_) => Ok(true),
            User::Anon => Ok(false),
        }
    }
}
