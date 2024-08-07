use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type BasicAuthCredentials = BasicAuthProof;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicAuthProof {
    username: String,
    password: String,
}

impl BasicAuthProof {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        BasicAuthProof {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl TryFrom<Vec<u8>> for BasicAuthProof {
    type Error = BasicAuthProofError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let header_value: String = String::from_utf8(bytes.to_vec())
            .map_err(|_| BasicAuthProofError::InvalidHeaderEncoding)?;

        let split = header_value.split_once(' ');

        match split {
            Some((name, contents)) if name == "Basic" => {
                let decoded: Vec<u8> =
                    base64::engine::general_purpose::STANDARD
                        .decode(contents)
                        .map_err(|_| BasicAuthProofError::InvalidAuthenticationValue)?;

                let decoded = String::from_utf8(decoded)
                    .map_err(|_| BasicAuthProofError::InvalidAuthenticationValue)?;

                if let Some((id, password)) = decoded.split_once(':') {
                    Ok(BasicAuthProof {
                        username: id.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    Err(BasicAuthProofError::MissingPassword)
                }
            }
            _ => Err(BasicAuthProofError::InvalidAuthenticationType),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum BasicAuthProofError {
    #[error("invalid authentication type")]
    InvalidAuthenticationType,
    #[error("invalid authentication value")]
    InvalidAuthenticationValue,
    #[error("missing passsword")]
    MissingPassword,
    #[error("invalid header encoding")]
    InvalidHeaderEncoding, // Do we need this?
}
