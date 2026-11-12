//! Access-token (JWT) issuing and verification.
//!
//! Security properties:
//! * The accepted algorithm is fixed to HS256 by *our* `Validation`; the token header's
//!   `alg` is never used to select a verification method (so `alg: none` and algorithm
//!   confusion are rejected).
//! * `exp`, `iss`, `aud` and `sub` are required and checked, with zero leeway.
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// User id.
    pub sub: String,
    /// Role name at issue time (authorization re-reads the role from the database).
    pub role: String,
    /// Session family id: lets the server reject tokens whose session was revoked.
    pub sid: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Clone)]
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    audience: String,
    validation: Validation,
}

impl JwtKeys {
    pub fn new(secret: &[u8], issuer: &str, audience: &str) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 0;
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            validation,
        }
    }

    /// Issue a token valid for `ttl_secs`. Returns `(token, ttl_secs)`.
    pub fn issue(
        &self,
        user_id: Uuid,
        role: &str,
        sid: Uuid,
        ttl_secs: i64,
    ) -> Result<(String, i64), AppError> {
        self.issue_at(user_id, role, sid, chrono::Utc::now().timestamp(), ttl_secs)
    }

    pub fn issue_at(
        &self,
        user_id: Uuid,
        role: &str,
        sid: Uuid,
        now: i64,
        ttl_secs: i64,
    ) -> Result<(String, i64), AppError> {
        let claims = Claims {
            sub: user_id.to_string(),
            role: role.to_string(),
            sid: sid.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp: now + ttl_secs,
            jti: Uuid::new_v4().to_string(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map(|t| (t, ttl_secs))
            .map_err(AppError::internal)
    }

    pub fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        decode::<Claims>(token, &self.decoding, &self.validation).map(|d| d.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123";

    fn keys() -> JwtKeys {
        JwtKeys::new(SECRET, "iss-a", "aud-a")
    }

    #[test]
    fn roundtrip() {
        let (uid, sid) = (Uuid::new_v4(), Uuid::new_v4());
        let (tok, ttl) = keys().issue(uid, "ANALYST", sid, 900).unwrap();
        assert_eq!(ttl, 900);
        let c = keys().verify(&tok).unwrap();
        assert_eq!(c.sub, uid.to_string());
        assert_eq!(c.sid, sid.to_string());
        assert_eq!(c.role, "ANALYST");
        assert_eq!(c.exp - c.iat, 900);
    }

    #[test]
    fn expired_token_is_rejected() {
        let past = chrono::Utc::now().timestamp() - 1000;
        let (tok, _) = keys()
            .issue_at(Uuid::new_v4(), "VIEWER", Uuid::new_v4(), past, 900)
            .unwrap();
        assert!(keys().verify(&tok).is_err());
    }

    #[test]
    fn wrong_signature_issuer_and_audience_are_rejected() {
        let (tok, _) = keys()
            .issue(Uuid::new_v4(), "ADMIN", Uuid::new_v4(), 900)
            .unwrap();
        let other_secret = JwtKeys::new(b"ffffffffffffffffffffffffffffffffffff", "iss-a", "aud-a");
        assert!(other_secret.verify(&tok).is_err());
        assert!(JwtKeys::new(SECRET, "iss-b", "aud-a").verify(&tok).is_err());
        assert!(JwtKeys::new(SECRET, "iss-a", "aud-b").verify(&tok).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (tok, _) = keys()
            .issue(Uuid::new_v4(), "VIEWER", Uuid::new_v4(), 900)
            .unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims["role"] = "ADMIN".into();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            parts[2]
        );
        assert!(keys().verify(&forged).is_err());
    }

    #[test]
    fn alg_none_is_rejected() {
        let (tok, _) = keys()
            .issue(Uuid::new_v4(), "ADMIN", Uuid::new_v4(), 900)
            .unwrap();
        let payload = tok.split('.').nth(1).unwrap();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        assert!(keys().verify(&format!("{header}.{payload}.")).is_err());
    }

    #[test]
    fn other_hmac_algorithms_are_rejected_even_with_the_right_secret() {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            role: "ADMIN".into(),
            sid: Uuid::new_v4().to_string(),
            iss: "iss-a".into(),
            aud: "aud-a".into(),
            iat: now,
            exp: now + 900,
            jti: "x".into(),
        };
        let tok = encode(
            &Header::new(Algorithm::HS512),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(
            keys().verify(&tok).is_err(),
            "header alg must not select the algorithm"
        );
    }

    #[test]
    fn missing_required_claims_are_rejected() {
        #[derive(Serialize)]
        struct NoExp {
            sub: String,
            iss: String,
            aud: String,
        }
        let tok = encode(
            &Header::new(Algorithm::HS256),
            &NoExp {
                sub: "x".into(),
                iss: "iss-a".into(),
                aud: "aud-a".into(),
            },
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(keys().verify(&tok).is_err());
    }
}
