use std::{convert::Infallible, marker::PhantomData};

use axum::{async_trait, http::request::Parts};

use crate::{AuthzBackend, User};

/// Allows the request only if the user has the specified role.
#[derive(Debug, Clone)]
pub struct RoleAuthzBackend<U>
where
    U: UserWithRoles + std::fmt::Debug + Clone + Send + Sync + 'static,
{
    role: String,
    _marker: PhantomData<U>,
}

impl<U> RoleAuthzBackend<U>
where
    U: UserWithRoles + std::fmt::Debug + Clone + Send + Sync + 'static,
{
    pub fn new(role: impl Into<String>) -> Self {
        RoleAuthzBackend {
            role: role.into(),
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<U> AuthzBackend<U> for RoleAuthzBackend<U>
where
    U: UserWithRoles + std::fmt::Debug + Clone + Send + Sync + 'static,
{
    type Error = Infallible;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let user = req_parts
            .extensions
            .get::<User<U>>()
            .expect("Is AuthnLayer enabled?");

        match user {
            User::Auth(user) => Ok(user.roles().contains(&self.role)),
            User::Anon => Ok(false),
        }
    }
}

pub trait UserWithRoles {
    fn roles(&self) -> std::collections::HashSet<String>;
}
