use std::{error, fs::Permissions};

use axum::{
    async_trait,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::{authentication::User, authorization::AuthorizationBackend};

#[derive(Debug, Clone)]
pub struct AndAuthorizationBackend<T, E> {
    first: T,
    second: E,
}

impl<T, E> AndAuthorizationBackend<T, E> {
    pub fn new(first: T, second: E) -> Self{
        AndAuthorizationBackend {
            first,
            second
        }
    }
}

#[derive(Error, Debug)]
pub enum AndAuthorizationBackendError<
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
> {
    #[error(transparent)]
    FirstOperandError(T),
    #[error(transparent)]
    SecondOperandError(E),
}

impl<T: std::error::Error + IntoResponse, E: std::error::Error + IntoResponse> IntoResponse
    for AndAuthorizationBackendError<T, E>
{
    fn into_response(self) -> Response {
        match self {
            Self::FirstOperandError(err) => err.into_response(),
            Self::SecondOperandError(err) => err.into_response(),
        }
    }
}

#[async_trait]
impl<U: User + Send + Sync, T: AuthorizationBackend<U>, E: AuthorizationBackend<U>>
    AuthorizationBackend<U> for AndAuthorizationBackend<T, E>
{
    type Error = AndAuthorizationBackendError<T::Error, E::Error>;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let first = self
            .first
            .authorize(req_parts)
            .await
            .map_err(|err| AndAuthorizationBackendError::FirstOperandError(err))?;

        if first {
            let second = self
                .second
                .authorize(req_parts)
                .await
                .map_err(|err| AndAuthorizationBackendError::SecondOperandError(err))?;

            Ok(second)
        } else {
            Ok(false)
        }
    }
}
