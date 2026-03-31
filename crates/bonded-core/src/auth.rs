use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteToken {
    pub token: String,
    pub expires_at: String,
    pub uses_remaining: u32,
}

impl InviteToken {
    pub fn is_usable(&self) -> bool {
        self.uses_remaining > 0
    }
}

#[cfg(test)]
mod tests {
    use super::InviteToken;

    #[test]
    fn token_is_usable_when_remaining_uses_exist() {
        let token = InviteToken {
            token: "abc".to_owned(),
            expires_at: "2026-03-31T00:00:00Z".to_owned(),
            uses_remaining: 1,
        };
        assert!(token.is_usable());
    }

    #[test]
    fn token_not_usable_when_uses_are_zero() {
        let token = InviteToken {
            token: "abc".to_owned(),
            expires_at: "2026-03-31T00:00:00Z".to_owned(),
            uses_remaining: 0,
        };
        assert!(!token.is_usable());
    }
}
