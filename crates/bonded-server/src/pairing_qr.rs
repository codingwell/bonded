use bonded_core::auth::InviteToken;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct PairingPayload {
    pub server_public_address: String,
    pub invite_token: String,
    pub server_public_key: String,
}

pub fn emit_pairing_qr(
    public_address: &str,
    invite: &InviteToken,
    server_public_key: &str,
) -> Option<String> {
    let payload_json = match build_pairing_payload_json(public_address, invite, server_public_key) {
        Some(payload) => payload,
        None => {
            warn!("server public address not configured; skipping startup pairing QR emission");
            return None;
        }
    };

    let qr = match QrCode::new(payload_json.as_bytes()) {
        Ok(code) => code,
        Err(err) => {
            warn!(error = %err, "failed to generate pairing QR");
            return None;
        }
    };

    let rendered = qr.render::<unicode::Dense1x2>().build();
    info!(payload = %payload_json, "pairing payload json");
    info!("startup pairing qr:\n{}", rendered);
    Some(payload_json)
}

fn build_pairing_payload_json(
    public_address: &str,
    invite: &InviteToken,
    server_public_key: &str,
) -> Option<String> {
    if public_address.trim().is_empty() {
        return None;
    }

    let payload = PairingPayload {
        server_public_address: public_address.to_owned(),
        invite_token: invite.token.clone(),
        server_public_key: server_public_key.to_owned(),
    };
    serde_json::to_string(&payload).ok()
}

#[cfg(test)]
mod tests {
    use super::{build_pairing_payload_json, PairingPayload};
    use bonded_core::auth::InviteToken;

    #[test]
    fn payload_contains_required_fields() {
        let invite = InviteToken {
            token: "token-123".to_owned(),
            expires_at: "unix:123".to_owned(),
            uses_remaining: 1,
        };

        let json = build_pairing_payload_json(
            "bonded.example.com:8080",
            &invite,
            "pub-key",
        )
        .expect("payload json should build");

        let parsed: PairingPayload = serde_json::from_str(&json).expect("payload should parse");
        assert_eq!(parsed.server_public_address, "bonded.example.com:8080");
        assert_eq!(parsed.invite_token, "token-123");
        assert_eq!(parsed.server_public_key, "pub-key");
    }

    #[test]
    fn empty_public_address_skips_payload() {
        let invite = InviteToken {
            token: "token-123".to_owned(),
            expires_at: "unix:123".to_owned(),
            uses_remaining: 1,
        };

        let payload = build_pairing_payload_json("", &invite, "pub-key");
        assert!(payload.is_none());
    }
}
