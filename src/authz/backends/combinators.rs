use axum::{
    async_trait,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use thiserror::Error;

use crate::AuthzBackend;

/// Combines two authorization backends in a short circuit fashion.
/// The request is allowed only if one of the backends allow the request
#[derive(Debug, Clone)]
pub struct OrAuthzBackend<T, E> {
    first: T,
    second: E,
}

impl<T, E> OrAuthzBackend<T, E> {
    pub fn new(first: T, second: E) -> Self {
        OrAuthzBackend { first, second }
    }
}
#[derive(Error, Debug)]
pub enum OrAuthzBackendError<T, E>
where
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
{
    #[error(transparent)]
    FirstOperandError(T),
    #[error(transparent)]
    SecondOperandError(E),
}

impl<T, E> IntoResponse for OrAuthzBackendError<T, E>
where
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Self::FirstOperandError(err) => err.into_response(),
            Self::SecondOperandError(err) => err.into_response(),
        }
    }
}

#[async_trait]
impl<U, T, E> AuthzBackend<U> for OrAuthzBackend<T, E>
where
    T: AuthzBackend<U>,
    E: AuthzBackend<U>,
{
    type Error = OrAuthzBackendError<T::Error, E::Error>;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let first = self
            .first
            .authorize(req_parts)
            .await
            .map_err(|err| OrAuthzBackendError::FirstOperandError(err))?;

        if first {
            Ok(first)
        } else {
            let second = self
                .second
                .authorize(req_parts)
                .await
                .map_err(|err| OrAuthzBackendError::SecondOperandError(err))?;
            Ok(second)
        }
    }
}

/// Combines two authorization backends in a short circuit fashion.
/// The request is allowed only if both of the backends allow the requests.
#[derive(Debug, Clone)]
pub struct AndAuthzBackend<T, E> {
    first: T,
    second: E,
}

impl<T, E> AndAuthzBackend<T, E> {
    pub fn new(first: T, second: E) -> Self {
        AndAuthzBackend { first, second }
    }
}

#[derive(Error, Debug)]
pub enum AndAuthzBackendError<T, E>
where
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
{
    #[error(transparent)]
    FirstOperandError(T),
    #[error(transparent)]
    SecondOperandError(E),
}

impl<T, E> IntoResponse for AndAuthzBackendError<T, E>
where
    T: std::error::Error + IntoResponse,
    E: std::error::Error + IntoResponse,
{
    fn into_response(self) -> Response {
        match self {
            Self::FirstOperandError(err) => err.into_response(),
            Self::SecondOperandError(err) => err.into_response(),
        }
    }
}

#[async_trait]
impl<U, T, E> AuthzBackend<U> for AndAuthzBackend<T, E>
where
    T: AuthzBackend<U>,
    E: AuthzBackend<U>,
{
    type Error = AndAuthzBackendError<T::Error, E::Error>;

    async fn authorize(&self, req_parts: &Parts) -> Result<bool, Self::Error> {
        let first = self
            .first
            .authorize(req_parts)
            .await
            .map_err(|err| AndAuthzBackendError::FirstOperandError(err))?;

        if first {
            let second = self
                .second
                .authorize(req_parts)
                .await
                .map_err(|err| AndAuthzBackendError::SecondOperandError(err))?;

            Ok(second)
        } else {
            Ok(false)
        }
    }
}
