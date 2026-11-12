//! Argon2id password hashing and the password policy.
//! Parameters are the `argon2` crate defaults (Argon2id, v19, m=19456 KiB, t=2, p=1),
//! which match the OWASP minimum recommendation.
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::error::AppError;

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 128;

pub fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(AppError::internal)
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Hashing is CPU- and memory-heavy: keep it off the async executor threads.
pub async fn hash_async(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(AppError::internal)?
}

pub async fn verify_async(password: String, phc: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &phc))
        .await
        .unwrap_or(false)
}

const COMMON: &[&str] = &[
    "password1234",
    "passwordpassword",
    "123456789012",
    "1234567890123",
    "qwertyuiop12",
    "qwertyuiopasdf",
    "administrator",
    "letmein123456",
    "iloveyou12345",
];

/// Length-based policy (NIST SP 800-63B style): no composition rules, but a minimum
/// length, a maximum to bound hashing cost, and a few obvious rejections.
pub fn validate_new_password(password: &str, username: &str) -> Result<(), AppError> {
    let n = password.chars().count();
    if n < MIN_PASSWORD_CHARS {
        return Err(AppError::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        )));
    }
    if n > MAX_PASSWORD_CHARS {
        return Err(AppError::BadRequest(format!(
            "password must be at most {MAX_PASSWORD_CHARS} characters"
        )));
    }
    let lower = password.to_lowercase();
    if !username.is_empty() && lower.contains(&username.to_lowercase()) {
        return Err(AppError::BadRequest(
            "password must not contain the username".to_string(),
        ));
    }
    let first = password.chars().next();
    if password.chars().all(|c| Some(c) == first) || COMMON.contains(&lower.as_str()) {
        return Err(AppError::BadRequest("password is too common".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_argon2id_with_expected_params_and_verifies() {
        let h = hash_password("correct-horse-battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert!(verify_password("correct-horse-battery", &h));
        assert!(!verify_password("wrong-horse-battery", &h));
    }

    #[test]
    fn salts_are_unique() {
        assert_ne!(
            hash_password("same-password-1").unwrap(),
            hash_password("same-password-1").unwrap()
        );
    }

    #[test]
    fn garbage_hash_never_verifies() {
        assert!(!verify_password("x", "not-a-phc-string"));
        assert!(!verify_password("x", ""));
    }

    #[test]
    fn policy() {
        assert!(validate_new_password("short", "bob").is_err());
        assert!(validate_new_password(&"a".repeat(129), "bob").is_err());
        assert!(validate_new_password("MyBobPassword123", "bob").is_err());
        assert!(validate_new_password("aaaaaaaaaaaa", "bob").is_err());
        assert!(validate_new_password("Password1234", "bob").is_err());
        assert!(validate_new_password("correct-horse-battery", "bob").is_ok());
        // length is counted in characters, not bytes
        assert!(validate_new_password("ééééééééééé1", "bob").is_ok());
    }
}
