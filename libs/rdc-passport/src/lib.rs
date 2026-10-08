//! Device passports.
//!
//! Wire format, one line, no padding anywhere:
//!
//! ```text
//! rdcp1.<b64u ikc body>.<b64u ikc sig>.<b64u passport body>.<b64u passport sig>
//! ```
//!
//! * The issuing-key certificate (ikc) is signed by a CA root key that verifiers already trust.
//! * The passport is signed by the issuing key named in the ikc.
//! * Every signature covers a domain prefix plus the exact body bytes, so a signature made for one
//!   kind of object can never be replayed as another, and nothing is re-serialized before checking.
//! * Bodies are JSON with unknown fields rejected; a verifier first checks the signature over the
//!   bytes it received and only then parses them.
//!
//! A passport is not a secret: it binds the device's public keys. Proving possession of the
//! identity key on each connection is the caller's job.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "rdcp1";
pub const VERSION: u32 = 1;
const IKC_DOMAIN: &[u8] = b"rdcp1-ikc\0";
const PASSPORT_DOMAIN: &[u8] = b"rdcp1-passport\0";
const RENEW_DOMAIN: &[u8] = b"rdcp1-renew\0";
const KEYUPDATE_DOMAIN: &[u8] = b"rdcp1-keyupdate\0";
/// Upper bound on a whole token, to refuse absurd input before decoding anything.
pub const MAX_TOKEN_LEN: usize = 4096;
pub const SCOPES: [&str; 6] = ["hbbs", "hbbr", "rds", "chat", "rustdrop", "peer"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Malformed(&'static str),
    UntrustedRoot,
    BadIkcSignature,
    IkcNotYetValid,
    IkcExpired,
    BadSignature,
    NotYetValid,
    Expired,
    WrongIssuer,
    Unsupported(&'static str),
    StaleRequest,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// Issuing-key certificate body, signed by a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IkcBody {
    pub typ: String,
    pub v: u32,
    pub kid: String,
    /// The issuing key's Ed25519 public key, base64url.
    pub key: String,
    pub nbf: i64,
    pub exp: i64,
}

/// Passport body, signed by the issuing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassportBody {
    pub typ: String,
    pub v: u32,
    /// 128-bit random, lowercase hex.
    pub serial: String,
    /// RustDesk id.
    pub rid: String,
    /// RDS device id (uuid).
    pub did: String,
    /// Identity public key, base64url.
    pub idk: String,
    /// "ed25519" for now; "p256" reserved for TPM-held keys.
    pub idk_alg: String,
    /// RustDesk Ed25519 public key, base64url.
    pub rdk: String,
    /// How the identity key is held: "legacy" (it is the RustDesk key), "dpapi" or "tpm".
    pub prot: String,
    pub scopes: Vec<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// kid of the issuing key that signed this passport.
    pub ikid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub passport: PassportBody,
    pub ikc: IkcBody,
    /// Past `exp` but inside the caller's grace window.
    pub in_grace: bool,
}

/// Clock tolerance and grace the verifier applies, in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    pub now: i64,
    pub skew: i64,
    pub grace: i64,
}

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>, Error> {
    B64.decode(text).map_err(|_| Error::Malformed("base64"))
}

/// kid = first 8 bytes of SHA-256 over the raw issuing public key, lowercase hex.
pub fn kid_for(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// Short fingerprint of any public key for display and for the two-box list: SHA-256, first 16 bytes, hex.
pub fn fingerprint(raw_public_key: &[u8]) -> String {
    let digest = Sha256::digest(raw_public_key);
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn signed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

fn verifying_key(raw: &[u8]) -> Result<VerifyingKey, Error> {
    let raw: [u8; 32] = raw.try_into().map_err(|_| Error::Malformed("key length"))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| Error::Malformed("key"))
}

fn signature(raw: &[u8]) -> Result<Signature, Error> {
    let raw: [u8; 64] = raw.try_into().map_err(|_| Error::Malformed("signature length"))?;
    Ok(Signature::from_bytes(&raw))
}

/// Root signs a new issuing key. Returns "<b64u body>.<b64u sig>".
pub fn sign_ikc(root: &SigningKey, issuing: &VerifyingKey, nbf: i64, exp: i64) -> String {
    let body = IkcBody {
        typ: "rdc-ikc".into(),
        v: VERSION,
        kid: kid_for(issuing),
        key: b64(issuing.as_bytes()),
        nbf,
        exp,
    };
    let bytes = serde_json::to_vec(&body).expect("ikc serializes");
    let sig = root.sign(&signed(IKC_DOMAIN, &bytes));
    format!("{}.{}", b64(&bytes), b64(&sig.to_bytes()))
}

/// Issuing key signs a passport. `ikc` is the string returned by [`sign_ikc`].
pub fn sign_passport(issuing: &SigningKey, ikc: &str, body: &PassportBody) -> String {
    let bytes = serde_json::to_vec(body).expect("passport serializes");
    let sig = issuing.sign(&signed(PASSPORT_DOMAIN, &bytes));
    format!("{PREFIX}.{ikc}.{}.{}", b64(&bytes), b64(&sig.to_bytes()))
}

/// Strict verification against a set of trusted root public keys.
pub fn verify(token: &str, roots: &[VerifyingKey], window: Window) -> Result<Verified, Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::Malformed("too long"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 || parts[0] != PREFIX {
        return Err(Error::Malformed("shape"));
    }
    let ikc_bytes = unb64(parts[1])?;
    let ikc_sig = signature(&unb64(parts[2])?)?;
    let body_bytes = unb64(parts[3])?;
    let body_sig = signature(&unb64(parts[4])?)?;

    let ikc_message = signed(IKC_DOMAIN, &ikc_bytes);
    if !roots.iter().any(|root| root.verify(&ikc_message, &ikc_sig).is_ok()) {
        return Err(if roots.is_empty() { Error::UntrustedRoot } else { Error::BadIkcSignature });
    }
    let ikc: IkcBody = serde_json::from_slice(&ikc_bytes).map_err(|_| Error::Malformed("ikc json"))?;
    if ikc.typ != "rdc-ikc" || ikc.v != VERSION {
        return Err(Error::Unsupported("ikc type/version"));
    }
    if window.now + window.skew < ikc.nbf {
        return Err(Error::IkcNotYetValid);
    }
    if window.now - window.skew > ikc.exp {
        return Err(Error::IkcExpired);
    }
    let issuing = verifying_key(&unb64(&ikc.key)?)?;
    if kid_for(&issuing) != ikc.kid {
        return Err(Error::Malformed("kid"));
    }

    issuing
        .verify(&signed(PASSPORT_DOMAIN, &body_bytes), &body_sig)
        .map_err(|_| Error::BadSignature)?;
    let passport: PassportBody =
        serde_json::from_slice(&body_bytes).map_err(|_| Error::Malformed("passport json"))?;
    if passport.typ != "rdc-passport" || passport.v != VERSION {
        return Err(Error::Unsupported("passport type/version"));
    }
    if passport.ikid != ikc.kid {
        return Err(Error::WrongIssuer);
    }
    if passport.idk_alg != "ed25519" {
        return Err(Error::Unsupported("idk_alg"));
    }
    verifying_key(&unb64(&passport.idk)?)?;
    verifying_key(&unb64(&passport.rdk)?)?;
    if window.now + window.skew < passport.nbf {
        return Err(Error::NotYetValid);
    }
    if window.now - window.skew > passport.exp + window.grace.max(0) {
        return Err(Error::Expired);
    }
    let in_grace = window.now - window.skew > passport.exp;
    Ok(Verified { passport, ikc, in_grace })
}

/// A device's renewal request, signed with its identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewBody {
    pub typ: String,
    pub v: u32,
    pub rid: String,
    pub did: String,
    pub idk: String,
    pub ts: i64,
    pub nonce: String,
}

/// Moving a device to a new identity key, signed by the old key and by the new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyUpdateBody {
    pub typ: String,
    pub v: u32,
    pub rid: String,
    pub did: String,
    pub old_key: String,
    pub new_key: String,
    pub new_alg: String,
    pub prot: String,
    pub ts: i64,
    pub nonce: String,
}

/// "<b64u body>.<b64u sig>" for a renewal, signed by the identity key.
pub fn sign_renew(identity: &SigningKey, body: &RenewBody) -> String {
    let bytes = serde_json::to_vec(body).expect("renew serializes");
    let sig = identity.sign(&signed(RENEW_DOMAIN, &bytes));
    format!("{}.{}", b64(&bytes), b64(&sig.to_bytes()))
}

/// Checks a renewal: signature by `expected_idk`, field match, freshness. The caller checks the nonce
/// has not been seen.
pub fn verify_renew(
    request: &str,
    expected_idk: &VerifyingKey,
    now: i64,
    max_age: i64,
) -> Result<RenewBody, Error> {
    let (bytes, sig) = split_two(request)?;
    expected_idk
        .verify(&signed(RENEW_DOMAIN, &bytes), &sig)
        .map_err(|_| Error::BadSignature)?;
    let body: RenewBody = serde_json::from_slice(&bytes).map_err(|_| Error::Malformed("renew json"))?;
    if body.typ != "rdc-renew" || body.v != VERSION {
        return Err(Error::Unsupported("renew type/version"));
    }
    if unb64(&body.idk)? != expected_idk.as_bytes() {
        return Err(Error::WrongIssuer);
    }
    if (now - body.ts).abs() > max_age {
        return Err(Error::StaleRequest);
    }
    Ok(body)
}

/// "<b64u body>.<b64u sig by old key>.<b64u sig by new key>".
pub fn sign_key_update(old: &SigningKey, new: &SigningKey, body: &KeyUpdateBody) -> String {
    let bytes = serde_json::to_vec(body).expect("key update serializes");
    let message = signed(KEYUPDATE_DOMAIN, &bytes);
    format!(
        "{}.{}.{}",
        b64(&bytes),
        b64(&old.sign(&message).to_bytes()),
        b64(&new.sign(&message).to_bytes())
    )
}

/// Checks a key update: signed by the key on file (`expected_old`) and by the new key it names.
pub fn verify_key_update(
    request: &str,
    expected_old: &VerifyingKey,
    now: i64,
    max_age: i64,
) -> Result<(KeyUpdateBody, VerifyingKey), Error> {
    if request.len() > MAX_TOKEN_LEN {
        return Err(Error::Malformed("too long"));
    }
    let parts: Vec<&str> = request.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Malformed("shape"));
    }
    let bytes = unb64(parts[0])?;
    let message = signed(KEYUPDATE_DOMAIN, &bytes);
    expected_old
        .verify(&message, &signature(&unb64(parts[1])?)?)
        .map_err(|_| Error::BadSignature)?;
    let body: KeyUpdateBody =
        serde_json::from_slice(&bytes).map_err(|_| Error::Malformed("key update json"))?;
    if body.typ != "rdc-keyupdate" || body.v != VERSION || body.new_alg != "ed25519" {
        return Err(Error::Unsupported("key update type/version/alg"));
    }
    if unb64(&body.old_key)? != expected_old.as_bytes() {
        return Err(Error::WrongIssuer);
    }
    let new = verifying_key(&unb64(&body.new_key)?)?;
    new.verify(&message, &signature(&unb64(parts[2])?)?)
        .map_err(|_| Error::BadSignature)?;
    if (now - body.ts).abs() > max_age {
        return Err(Error::StaleRequest);
    }
    Ok((body, new))
}

fn split_two(request: &str) -> Result<(Vec<u8>, Signature), Error> {
    if request.len() > MAX_TOKEN_LEN {
        return Err(Error::Malformed("too long"));
    }
    let parts: Vec<&str> = request.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::Malformed("shape"));
    }
    Ok((unb64(parts[0])?, signature(&unb64(parts[1])?)?))
}

pub fn parse_public_key(b64_key: &str) -> Result<VerifyingKey, Error> {
    verifying_key(&unb64(b64_key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn body(identity: &SigningKey, issuing: &SigningKey, nbf: i64, exp: i64) -> PassportBody {
        PassportBody {
            typ: "rdc-passport".into(),
            v: VERSION,
            serial: "00112233445566778899aabbccddeeff".into(),
            rid: "123456789".into(),
            did: "6f1c2a3b-0000-4000-8000-000000000001".into(),
            idk: b64(identity.verifying_key().as_bytes()),
            idk_alg: "ed25519".into(),
            rdk: b64(key(9).verifying_key().as_bytes()),
            prot: "dpapi".into(),
            scopes: SCOPES.iter().map(|s| s.to_string()).collect(),
            iat: nbf,
            nbf,
            exp,
            ikid: kid_for(&issuing.verifying_key()),
        }
    }

    fn issue(root: &SigningKey, issuing: &SigningKey, identity: &SigningKey, nbf: i64, exp: i64) -> String {
        let ikc = sign_ikc(root, &issuing.verifying_key(), 0, 10_000_000);
        sign_passport(issuing, &ikc, &body(identity, issuing, nbf, exp))
    }

    const W: Window = Window { now: 1_000_000, skew: 600, grace: 7 * 86_400 };

    #[test]
    fn valid_passport_verifies() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let token = issue(&root, &issuing, &identity, 999_000, 1_086_400);
        let verified = verify(&token, &[root.verifying_key()], W).unwrap();
        assert_eq!(verified.passport.rid, "123456789");
        assert!(!verified.in_grace);
    }

    #[test]
    fn second_trusted_root_accepted() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let token = issue(&root, &issuing, &identity, 999_000, 1_086_400);
        assert!(verify(&token, &[key(7).verifying_key(), root.verifying_key()], W).is_ok());
    }

    #[test]
    fn wrong_root_rejected() {
        let token = issue(&key(1), &key(2), &key(3), 999_000, 1_086_400);
        assert_eq!(verify(&token, &[key(7).verifying_key()], W), Err(Error::BadIkcSignature));
        assert_eq!(verify(&token, &[], W), Err(Error::UntrustedRoot));
    }

    #[test]
    fn expired_rejected_grace_accepted() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let token = issue(&root, &issuing, &identity, 900_000, 990_000);
        let in_grace = verify(&token, &[root.verifying_key()], W).unwrap();
        assert!(in_grace.in_grace);
        let no_grace = Window { grace: 0, ..W };
        assert_eq!(verify(&token, &[root.verifying_key()], no_grace), Err(Error::Expired));
        let long_ago = issue(&root, &issuing, &identity, 1, 100);
        assert_eq!(verify(&long_ago, &[root.verifying_key()], W), Err(Error::Expired));
    }

    #[test]
    fn not_yet_valid_rejected_within_skew_accepted() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let soon = issue(&root, &issuing, &identity, 1_000_300, 1_090_000);
        assert!(verify(&soon, &[root.verifying_key()], W).is_ok());
        let later = issue(&root, &issuing, &identity, 1_005_000, 1_090_000);
        assert_eq!(verify(&later, &[root.verifying_key()], W), Err(Error::NotYetValid));
    }

    #[test]
    fn tampered_body_rejected() {
        let token = issue(&key(1), &key(2), &key(3), 999_000, 1_086_400);
        let parts: Vec<&str> = token.split('.').collect();
        let mut passport: PassportBody = serde_json::from_slice(&unb64(parts[3]).unwrap()).unwrap();
        passport.rid = "999999999".into();
        let forged = format!(
            "{}.{}.{}.{}.{}",
            parts[0],
            parts[1],
            parts[2],
            b64(&serde_json::to_vec(&passport).unwrap()),
            parts[4]
        );
        assert_eq!(verify(&forged, &[key(1).verifying_key()], W), Err(Error::BadSignature));
    }

    #[test]
    fn passport_from_uncertified_key_rejected() {
        let (root, issuing, rogue, identity) = (key(1), key(2), key(4), key(3));
        let ikc = sign_ikc(&root, &issuing.verifying_key(), 0, 10_000_000);
        let token = sign_passport(&rogue, &ikc, &body(&identity, &rogue, 999_000, 1_086_400));
        assert_eq!(verify(&token, &[root.verifying_key()], W), Err(Error::BadSignature));
    }

    #[test]
    fn wrong_issuer_id_rejected() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let ikc = sign_ikc(&root, &issuing.verifying_key(), 0, 10_000_000);
        let mut claims = body(&identity, &issuing, 999_000, 1_086_400);
        claims.ikid = "0000000000000000".into();
        let token = sign_passport(&issuing, &ikc, &claims);
        assert_eq!(verify(&token, &[root.verifying_key()], W), Err(Error::WrongIssuer));
    }

    #[test]
    fn expired_issuing_key_rejected() {
        let (root, issuing, identity) = (key(1), key(2), key(3));
        let ikc = sign_ikc(&root, &issuing.verifying_key(), 0, 500_000);
        let token = sign_passport(&issuing, &ikc, &body(&identity, &issuing, 999_000, 1_086_400));
        assert_eq!(verify(&token, &[root.verifying_key()], W), Err(Error::IkcExpired));
    }

    #[test]
    fn ikc_signature_not_reusable_as_passport_signature() {
        // Domain separation: the root's ikc signature must not validate a passport body.
        let (root, issuing) = (key(1), key(2));
        let ikc = sign_ikc(&root, &issuing.verifying_key(), 0, 10_000_000);
        let (ikc_body, ikc_sig) = ikc.split_once('.').unwrap();
        let token = format!("{PREFIX}.{ikc}.{ikc_body}.{ikc_sig}");
        assert!(verify(&token, &[root.verifying_key()], W).is_err());
    }

    #[test]
    fn malformed_inputs_rejected() {
        let roots = [key(1).verifying_key()];
        for bad in ["", "rdcp1", "rdcp1.a.b.c", "rdcp2.a.b.c.d", "rdcp1.!!.b.c.d", &"x".repeat(5000)] {
            assert!(verify(bad, &roots, W).is_err(), "{bad:.20}");
        }
    }

    #[test]
    fn unknown_fields_rejected() {
        let (root, issuing) = (key(1), key(2));
        let ikc = sign_ikc(&root, &issuing.verifying_key(), 0, 10_000_000);
        let mut value = serde_json::to_value(body(&key(3), &issuing, 999_000, 1_086_400)).unwrap();
        value["admin"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        let sig = issuing.sign(&signed(PASSPORT_DOMAIN, &bytes));
        let token = format!("{PREFIX}.{ikc}.{}.{}", b64(&bytes), b64(&sig.to_bytes()));
        assert_eq!(verify(&token, &[root.verifying_key()], W), Err(Error::Malformed("passport json")));
    }

    fn renew_body(identity: &SigningKey, ts: i64) -> RenewBody {
        RenewBody {
            typ: "rdc-renew".into(),
            v: VERSION,
            rid: "123456789".into(),
            did: "6f1c2a3b-0000-4000-8000-000000000001".into(),
            idk: b64(identity.verifying_key().as_bytes()),
            ts,
            nonce: "n1".into(),
        }
    }

    #[test]
    fn renew_checks() {
        let identity = key(3);
        let request = sign_renew(&identity, &renew_body(&identity, 1_000_000));
        assert!(verify_renew(&request, &identity.verifying_key(), 1_000_100, 600).is_ok());
        assert_eq!(verify_renew(&request, &identity.verifying_key(), 1_002_000, 600), Err(Error::StaleRequest));
        assert_eq!(verify_renew(&request, &key(5).verifying_key(), 1_000_100, 600), Err(Error::BadSignature));
        // Signed by the right key but naming a different idk.
        let mut other = renew_body(&identity, 1_000_000);
        other.idk = b64(key(5).verifying_key().as_bytes());
        let request = sign_renew(&identity, &other);
        assert_eq!(verify_renew(&request, &identity.verifying_key(), 1_000_100, 600), Err(Error::WrongIssuer));
    }

    #[test]
    fn key_update_checks() {
        let (old, new) = (key(3), key(6));
        let body = KeyUpdateBody {
            typ: "rdc-keyupdate".into(),
            v: VERSION,
            rid: "123456789".into(),
            did: "6f1c2a3b-0000-4000-8000-000000000001".into(),
            old_key: b64(old.verifying_key().as_bytes()),
            new_key: b64(new.verifying_key().as_bytes()),
            new_alg: "ed25519".into(),
            prot: "dpapi".into(),
            ts: 1_000_000,
            nonce: "n2".into(),
        };
        let request = sign_key_update(&old, &new, &body);
        let (_, got) = verify_key_update(&request, &old.verifying_key(), 1_000_000, 600).unwrap();
        assert_eq!(got, new.verifying_key());
        // The new key's signature is required: an old-key-only update is refused.
        let only_old = sign_key_update(&old, &key(8), &body);
        assert_eq!(verify_key_update(&only_old, &old.verifying_key(), 1_000_000, 600), Err(Error::BadSignature));
        // Not signed by the key on file.
        assert_eq!(verify_key_update(&request, &key(8).verifying_key(), 1_000_000, 600), Err(Error::BadSignature));
    }
}
