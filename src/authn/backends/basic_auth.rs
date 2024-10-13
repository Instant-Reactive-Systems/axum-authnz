use base64::Engine;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type BasicAuthCredentials = BasicAuthnProof;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicAuthnProof {
    pub username: String,
    pub password: String,
}

impl BasicAuthnProof {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        BasicAuthnProof {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl TryFrom<Vec<u8>> for BasicAuthnProof {
    type Error = BasicAuthnProofError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let header_value: String = String::from_utf8(bytes.to_vec())
            .map_err(|_| BasicAuthnProofError::InvalidHeaderEncoding)?;

        let split = header_value.split_once(' ');

        match split {
            Some((name, contents)) if name == "Basic" => {
                let decoded: Vec<u8> =
                    base64::engine::general_purpose::STANDARD
                        .decode(contents)
                        .map_err(|_| BasicAuthnProofError::InvalidAuthenticationValue)?;

                let decoded = String::from_utf8(decoded)
                    .map_err(|_| BasicAuthnProofError::InvalidAuthenticationValue)?;

                if let Some((id, password)) = decoded.split_once(':') {
                    Ok(BasicAuthnProof {
                        username: id.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    Err(BasicAuthnProofError::MissingPassword)
                }
            }
            _ => Err(BasicAuthnProofError::InvalidAuthenticationType),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub enum BasicAuthnProofError {
    #[error("invalid authentication type")]
    InvalidAuthenticationType,
    #[error("invalid authentication value")]
    InvalidAuthenticationValue,
    #[error("missing passsword")]
    MissingPassword,
    #[error("invalid header encoding")]
    InvalidHeaderEncoding, // Do we need this?
}
