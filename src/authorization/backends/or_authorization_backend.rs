use std::{error, fs::Permissions};

use axum::{
    async_trait, http::request::Parts, response::{IntoResponse, Response}
};
use thiserror::Error;

use crate::{
    authentication::User,
    authorization::{AuthorizationBackend},
};

/// Combines two authorization backends in a short circuit fashion.
/// The request is allowed only if one of the backends allow the request
#[derive(Debug, Clone)]
pub struct OrAuthorizationBackend<T, E> {
    first: T,
    second: E,
}

impl<T, E> OrAuthorizationBackend<T, E> {
    pub fn new(first: T, second: E) -> Self{
        OrAuthorizationBackend {
            first,
            second
        }
    }
}
#[derive(Error, Debug)]
pub enum OrAuthorizationBackendError<
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
> {
    #[error(transparent)]
    FirstOperandError(T),
    #[error(transparent)]
    SecondOperandError(E),
}

impl<T: std::error::Error + IntoResponse, E: std::error::Error + IntoResponse> IntoResponse
    for OrAuthorizationBackendError<T, E>
{
    fn into_response(self) -> Response {
        match self {
            Self::FirstOperandError(err) => err.into_response(),
            Self::SecondOperandError(err) => err.into_response(),
        }
    }
}

#[async_trait]
impl<
        U: User + Send + Sync,
        T: AuthorizationBackend<U>,
        E: AuthorizationBackend<U>,
    > AuthorizationBackend<U> for OrAuthorizationBackend<T, E>
{
    type Error = OrAuthorizationBackendError<T::Error, E::Error>;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
       
        let first = self
            .first
            .authorize(req_parts)
            .await
            .map_err(|err| OrAuthorizationBackendError::FirstOperandError(err))?;

        if first {
            Ok(first)
        } else {
            let second = self
                .second
                .authorize(req_parts)
                .await
                .map_err(|err| OrAuthorizationBackendError::SecondOperandError(err))?;
            Ok(second)
        }
    }
}
