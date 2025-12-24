use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit},
};
use anyhow::{Result, bail};
use base64::prelude::*;
use bincode::{Decode, Encode};
use ed25519_dalek::Signature;
use ed25519_dalek::ed25519::SignatureBytes;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use ml_kem::{
    EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
};
use rand::Rng;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type NodeId = [u8; 32];
pub type ShortId = [u8; 12];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicIdentity {
    pub public_key: NodeId,
}

impl PublicIdentity {
    pub fn short_id(&self) -> ShortId {
        self.public_key[0..12]
            .try_into()
            .expect("couldn't convert NodeId into ShortId")
    }
}

impl std::fmt::Display for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base64())
    }
}

impl PublicIdentity {
    pub fn verify(&self, msg: Vec<u8>, signature: &SignatureBytes) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)?;
        let signature = Signature::from_bytes(signature);
        Ok(verifying_key.verify(msg.as_slice(), &signature).is_ok())
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key)
    }
}

#[derive(Clone, Debug)]
pub struct PrivateIdentity {
    private_key: [u8; 32],
    pub public_id: PublicIdentity,
}

impl PrivateIdentity {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Self {
            private_key: *signing_key.as_bytes(),
            public_id: PublicIdentity {
                public_key: *verifying_key.as_bytes(),
            },
        }
    }

    pub fn from_base64(base64: &str) -> Result<Self> {
        let mut private_key: [u8; 32] = [0; 32];
        BASE64_STANDARD.decode_slice(base64, &mut private_key)?;
        let public_key = *SigningKey::from_bytes(&private_key)
            .verifying_key()
            .as_bytes();
        Ok(Self {
            private_key,
            public_id: PublicIdentity { public_key },
        })
    }

    pub fn sign(&self, msg: Vec<u8>) -> SignatureBytes {
        let mut signing_key: SigningKey = SigningKey::from_bytes(&self.private_key);
        let signature = signing_key.sign(msg.as_slice());
        signature.to_bytes()
    }

    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(self.private_key)
    }
}

type MLKem768EncapsulationKey = [u8; 1184];
type MLKem768DecapsulationKey = [u8; 2400];
type MLKem768Ciphertext = [u8; 1088];
type MLKemSharedSecret = [u8; 32];

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
enum MLKemMessage {
    EncapsulationKey(MLKem768EncapsulationKey),
    Ciphertext(MLKem768Ciphertext),
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub struct KeyExchangeMessage {
    session_id: SessionId,
    public: [u8; 32],
    ml_kem: MLKemMessage,
}

impl KeyExchangeMessage {
    pub fn get_session_id(&self) -> &SessionId {
        &self.session_id
    }
}

pub struct KeyExchange {
    secret: EphemeralSecret,
    session_id: SessionId,
    ml_kem_msg: MLKemMessage,
    ml_kem_dk: Option<MLKem768DecapsulationKey>,
    ml_kem_secret: Option<MLKemSharedSecret>,
}

impl KeyExchange {
    pub fn new() -> Self {
        let mut osrng = OsRng;
        let secret = EphemeralSecret::random_from_rng(osrng);
        let mut session_id: SessionId = [0; 8];
        osrng.fill(&mut session_id);
        let (dk, ek) = MlKem768::generate(&mut osrng);
        Self {
            secret,
            session_id,
            ml_kem_msg: MLKemMessage::EncapsulationKey(ek.as_bytes().into()),
            ml_kem_dk: Some(dk.as_bytes().into()),
            ml_kem_secret: None,
        }
    }

    pub fn new_from_other_message(other_kex: &KeyExchangeMessage) -> Result<Self> {
        let mut osrng = OsRng;
        let secret = EphemeralSecret::random_from_rng(osrng);
        let session_id = other_kex.session_id;
        Ok(match other_kex.ml_kem {
            MLKemMessage::EncapsulationKey(k) => {
                let ek: EncapsulationKey<MlKem768Params> = EncapsulationKey::from_bytes(&k.into());
                let Ok((ct, ss)) = ek.encapsulate(&mut osrng) else {
                    bail!("mlkem encapsulation failed");
                };
                Self {
                    secret,
                    session_id,
                    ml_kem_msg: MLKemMessage::Ciphertext(ct.into()),
                    ml_kem_dk: None,
                    ml_kem_secret: Some(ss.into()),
                }
            }
            _ => bail!("wrong key exchange message type"),
        })
    }

    pub fn public(&self) -> KeyExchangeMessage {
        KeyExchangeMessage {
            session_id: self.session_id,
            public: PublicKey::from(&self.secret).to_bytes(),
            ml_kem: self.ml_kem_msg.clone(),
        }
    }

    pub fn get_session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn into_encryption_session(
        self,
        other_kex: &KeyExchangeMessage,
    ) -> Result<EncryptionSession> {
        if other_kex.session_id != self.session_id {
            bail!("session_id doesn't match")
        }
        let ml_kem_secret: MLKemSharedSecret = match (
            self.ml_kem_secret,
            self.ml_kem_msg,
            &other_kex.ml_kem,
            self.ml_kem_dk,
        ) {
            (None, MLKemMessage::EncapsulationKey(_), MLKemMessage::Ciphertext(ct), Some(dk)) => {
                let dk: DecapsulationKey<MlKem768Params> = DecapsulationKey::from_bytes(&dk.into());
                match dk.decapsulate(ct.into()) {
                    Ok(v) => v.into(),
                    Err(_) => bail!("can't decapsulate ml kem key"),
                }
            }
            (Some(ss), MLKemMessage::Ciphertext(_), MLKemMessage::EncapsulationKey(_), None) => ss,
            _ => bail!("got wrong kind of key exchange message for current key exchange"),
        };
        let mut new_session_id: [u8; 8] =
            PublicKey::from(&self.secret).to_bytes()[0..8].try_into()?;
        for (a, b) in new_session_id.iter_mut().zip(other_kex.public) {
            *a ^= b;
        }
        let mut secret_bytes = self
            .secret
            .diffie_hellman(&PublicKey::from(other_kex.public))
            .to_bytes();
        for (a, b) in secret_bytes.iter_mut().zip(ml_kem_secret.into_iter()) {
            *a ^= b;
        }
        Ok(EncryptionSession::new(new_session_id, secret_bytes))
    }
}

pub type SessionId = [u8; 8];

pub struct EncryptionSession {
    session_id: SessionId,
    key: Key<Aes256Gcm>,
    iv: [u8; 12],
}

#[derive(Eq, PartialEq, Encode, Decode, Clone, Hash, Debug)]
pub struct EncryptedMessage {
    pub iv: [u8; 12],
    pub session_id: SessionId,
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    pub fn get_session_id(&self) -> &SessionId {
        &self.session_id
    }
}

impl EncryptionSession {
    pub fn new(session_id: SessionId, key: [u8; 32]) -> Self {
        Self {
            session_id,
            key: key.into(),
            iv: Aes256Gcm::generate_nonce(OsRng).into(),
        }
    }

    pub fn get_session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn incr_iv(&mut self) {
        let mut rollover = true;
        for b in self.iv.iter_mut() {
            if rollover {
                (*b, rollover) = b.overflowing_add(1)
            } else {
                break;
            }
        }
    }

    pub fn encrypt(&mut self, plaintext: &Vec<u8>) -> Result<EncryptedMessage> {
        let cipher = Aes256Gcm::new(&self.key);
        self.incr_iv();
        let Ok(ciphertext) = cipher.encrypt(&self.iv.into(), plaintext.as_slice()) else {
            bail!("crypto error")
        };
        Ok(EncryptedMessage {
            iv: self.iv,
            session_id: self.session_id,
            ciphertext,
        })
    }

    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        if let Ok(plaintext) = cipher.decrypt(&message.iv.into(), message.ciphertext.as_slice()) {
            Ok(plaintext)
        } else {
            bail!("crypto error")
        }
    }
}
