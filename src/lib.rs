use async_trait::async_trait;

#[async_trait]
pub trait AuthenticationService: Clone + Send + Sync {
    type AuthenticationProof: AuthenticationProof;
    type Credentials: Send + Sync;
    type Error: std::error::Error + Send + Sync;

    async fn authenticate(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Self::AuthenticationProof, Self::Error>;

    async fn login(
        &mut self,
        credentials: Self::Credentials,
    ) -> Result<Self::AuthenticationProof, Self::Error>;

    async fn logout(
        &mut self,
        authentication_proof: Self::AuthenticationProof,
    ) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait AuthenticationProof: Clone + Send + Sync {
    type User: Send + Sync;
    async fn user(&self) -> Self::User;
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, fmt};

    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[derive(Debug, Clone)]
    struct InMemoryAuthenticationService {
        users: HashMap<String, String>,
    }

    #[derive(Debug)]
    struct SomeError;

    impl Error for SomeError {}

    impl fmt::Display for SomeError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Oh no, something bad went down")
        }
    }

    #[async_trait]
    impl AuthenticationService for InMemoryAuthenticationService {
        type AuthenticationProof = JwtAuthenticationProof;
        type Credentials = (String, String);
        type Error = SomeError;

        async fn authenticate(
            &self,
            credentials: Self::Credentials,
        ) -> Result<Self::AuthenticationProof, Self::Error> {
            let username = credentials.0;
            let password = credentials.1;

            if let Some(actual_password) = self.users.get(&username) {
                if password == *actual_password {
                    Ok(JwtAuthenticationProof {
                        jwt: format!("{}:{}", username, password),
                    })
                } else {
                    Err(SomeError)
                }
            } else {
                Err(SomeError)
            }
        }

        async fn login(
            &mut self,
            credentials: Self::Credentials,
        ) -> Result<Self::AuthenticationProof, Self::Error> {
        }

        async fn logout(
            &mut self,
            authentication_proof: Self::AuthenticationProof,
        ) -> Result<(), Self::Error> {
        }
    }

    #[derive(Debug, Clone)]
    struct TestUser {
        id: String,
    }

    #[derive(Debug, Clone)]
    struct JwtAuthenticationProof {
        jwt: String,
    }

    #[async_trait]
    impl AuthenticationProof for JwtAuthenticationProof {
        type User = TestUser;

        async fn user(&self) -> Self::User {
            TestUser {
                id: self.jwt.clone(),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn convert_authentication_proof_to_user() {
        let proof = JwtAuthenticationProof {
            jwt: "Im a JWT".into(),
        };

        let user = proof.user().await;

        assert_eq!(user.id, proof.jwt);
    }
}
