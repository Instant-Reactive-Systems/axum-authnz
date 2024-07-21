use std::{collections::HashSet, marker::PhantomData};

use axum::{async_trait, http::request::Parts, response::IntoResponse};
use backends::{
    and_authorization_backend::AndAuthorizationBackend,
    or_authorization_backend::OrAuthorizationBackend,
};

use crate::authentication::User;

pub mod backends;

/// Represents a backend for authorization
///
/// User
#[async_trait]
pub trait AuthorizationBackend<AuthzUser: User + Send + Sync>:
    std::fmt::Debug + Clone + Send + Sync
{
    type Error: std::error::Error + Send + Sync + IntoResponse;

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct AuthorizationBuilder<U: User + Send + Sync, B: AuthorizationBackend<U>> {
    authorization_backend: B,
    _marker: PhantomData<U>,
}

impl<U: User + Send + Sync, B1: AuthorizationBackend<U>> AuthorizationBuilder<U, B1> {
    pub fn new(self, authorization_backend: B1) -> Self {
        AuthorizationBuilder {
            authorization_backend,
            _marker: PhantomData,
        }
    }

    pub fn and<B2: AuthorizationBackend<U>>(
        self,
        authorization_backend: B2,
    ) -> AuthorizationBuilder<U, AndAuthorizationBackend<B1, B2>> {
        let backend =
            AndAuthorizationBackend::new(self.authorization_backend, authorization_backend);

        AuthorizationBuilder {
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }

    pub fn or<B2: AuthorizationBackend<U>>(
        self,
        authorization_backend: B2,
    ) -> AuthorizationBuilder<U, OrAuthorizationBackend<B1, B2>> {
        let backend =
            OrAuthorizationBackend::new(self.authorization_backend, authorization_backend);

        AuthorizationBuilder {
            authorization_backend: backend,
            _marker: PhantomData,
        }
    }

    pub fn build(self) -> AuthorizationService<U, B1> {
        AuthorizationService {
            authorization_backend: self.authorization_backend,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationService<U: User + Send + Sync, B: AuthorizationBackend<U>> {
    authorization_backend: B,
    _marker: PhantomData<U>,
}
