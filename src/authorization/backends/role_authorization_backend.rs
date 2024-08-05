use std::{convert::Infallible, marker::PhantomData};

use axum::{async_trait, http::request::Parts};

use crate::{
    authentication::{AuthUser, User, UserWithRoles},
    authorization::AuthorizationBackend,
};


/// Allows the request only if the user has the specified role
#[derive(Debug, Clone)]
pub struct RoleAuthorizationBackend<U: UserWithRoles + Send + Sync> {
    role: String,
    _marker: PhantomData<U>,
}

impl<U: UserWithRoles + Send + Sync> RoleAuthorizationBackend<U> {
    pub fn new(role: impl Into<String>) -> Self {
        RoleAuthorizationBackend {
            role: role.into(),
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<U: UserWithRoles + Send + Sync + 'static> AuthorizationBackend<U> for RoleAuthorizationBackend<U> {
    type Error = Infallible;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let user = req_parts
            .extensions
            .get::<AuthUser<U>>()
            .expect("Is authentication layer enabled?");

        match user {
            AuthUser::Authenticated(user) => Ok(user.roles().contains(&self.role)),
            AuthUser::Unaunthenticated => Ok(false),
        }
    }
}
