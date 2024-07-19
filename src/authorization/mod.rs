use axum::{async_trait, response::IntoResponse};

pub mod backends;

/// Represents a backend for authorization
#[async_trait]
pub trait AuthorizationBackend: std::fmt::Debug + Clone + Send + Sync {
    type Error: std::error::Error + Send + Sync + IntoResponse;
    type User: Send + Sync;
    type Permission: Send + Sync;

    /// Returns a result which is `true` when the provided user has the provided
    /// permission and otherwise is `false`.
    async fn authorize(
        &self,
        user: Option<&Self::User>,
        perm: Option<Self::Permission>,
    ) -> Result<bool, Self::Error>;
}

