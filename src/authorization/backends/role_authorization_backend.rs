use std::convert::Infallible;

use axum::{async_trait, http::request::Parts};

use crate::{authentication::User, authorization::AuthorizationBackend};

#[derive(Debug, Clone)]
pub struct RoleAuthorizationBackend {
    role: String,
}

#[async_trait]
impl<U: User + Send + Sync + 'static> AuthorizationBackend<U> for RoleAuthorizationBackend {
    type Error = Infallible;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let user = req_parts.extensions.get::<U>();

        if let Some(user) = user {
            Ok(user.roles().contains(&self.role))
        } else {
            Ok(false)
        }
    }
}
