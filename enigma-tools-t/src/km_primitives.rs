use crate::common::errors_t::{EnclaveError::{self, SystemError}, EnclaveSystemError::MessagingError};
use enigma_crypto::{symmetric, Encryption, CryptoError, hash};
use enigma_types::{ContractAddress, DhKey, StateKey, PubKey};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sgx_trts::trts::rsgx_read_rand;
use std::{string::ToString, vec::Vec};
use serde_json;

pub type MsgID = [u8; 12];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum PrincipalMessageType {
    Response(Vec<(ContractAddress, StateKey)>),
    Request(Option<Vec<ContractAddress>>),
    EncryptedResponse(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PrincipalMessage {
    pub data: PrincipalMessageType,
    pubkey: Vec<u8>,
    id: MsgID,
}

impl PrincipalMessage {

    pub fn new(data: PrincipalMessageType, pubkey: PubKey) -> Result<Self, EnclaveError> {
        let mut id = [0u8; 12];
        rsgx_read_rand(&mut id)?;
        let pubkey = pubkey.to_vec();
        Ok(Self { data, pubkey, id })
    }

    pub fn new_id(data: PrincipalMessageType, id: [u8; 12], pubkey: PubKey) -> Self {
        let pubkey = pubkey.to_vec();
        Self { data, pubkey, id }
    }

    pub fn to_sign(&self) -> Result<Vec<u8>, EnclaveError> {
        if self.is_response() {
            return Err(SystemError(MessagingError { err: "can't serialize non encrypted response".to_string() }));
        }
        let mut to_sign = Vec::with_capacity(3);
        match &self.data {
            PrincipalMessageType::Request(Some(addresses)) => {
                to_sign.push(hash::prepare_hash_multiple(addresses.as_ref()));
            }
            PrincipalMessageType::EncryptedResponse(v) => to_sign.push(v.clone()),
            PrincipalMessageType::Request(None) => (), // If the request is empty we don't need to sign on it.
            PrincipalMessageType::Response(_) => unreachable!() // This can't be reached because we check if it's a response before.
        }
        to_sign.push(self.pubkey.to_vec());
        to_sign.push(self.id.to_vec());
        Ok(hash::prepare_hash_multiple(&to_sign))
    }

    pub fn into_message(self) -> Result<Vec<u8>, EnclaveError> {
        if self.is_response() {
            return Err(SystemError(MessagingError { err: "can't serialize non encrypted response".to_string() }));
        }
        let mut buf = Vec::new();
        let val = serde_json::to_value(self)
            .map_err(|_| SystemError(MessagingError {err: "Couldn't convert PrincipalMessage to Value".to_string()}))?;
        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_message(msg: &[u8]) -> Result<Self, EnclaveError> {
        let mut des = Deserializer::new(msg);
        let res: serde_json::Value =
            Deserialize::deserialize(&mut des).map_err(|_| MessagingError { err: "can't deserialize the message" })?;
        let msg: Self = serde_json::from_value(res).map_err(|_| MessagingError { err: "can't deserialize the message" })?;
        if msg.pubkey.len() != 64 {
            return Err(essagingError { err: "the pub key is not in the right length" })
        }
        Ok(msg)
    }

    pub fn get_pubkey(&self) -> PubKey {
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&self.pubkey[..]);
        pubkey
    }

    pub fn get_id(&self) -> MsgID { self.id }

    pub fn is_request(&self) -> bool {
        if let PrincipalMessageType::Request(_) = self.data {
            true
        } else {
            false
        }
    }

    pub fn is_response(&self) -> bool {
        if let PrincipalMessageType::Response(_) = self.data {
            true
        } else {
            false
        }
    }

    pub fn is_encrypted_response(&self) -> bool {
        if let PrincipalMessageType::EncryptedResponse(_) = self.data {
            true
        } else {
            false
        }
    }
}

impl<'a> Encryption<&'a DhKey, CryptoError, Self, [u8; 12]> for PrincipalMessage {
    fn encrypt_with_nonce(self, key: &DhKey, _iv: Option<[u8; 12]>) -> Result<Self, CryptoError> {
        match self.data {
            PrincipalMessageType::Response(response) => {
                let mut buf = Vec::new();
                response.serialize(&mut Serializer::new(&mut buf)).map_err(|_| CryptoError::EncryptionError)?;
                let enc = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
                Ok(Self { data: PrincipalMessageType::EncryptedResponse(enc), pubkey: self.pubkey, id: self.id })
            }
            _ => Err(CryptoError::EncryptionError ),
        }
    }

    fn decrypt(enc: Self, key: &DhKey) -> Result<Self, CryptoError> {
        match &enc.data {
            PrincipalMessageType::EncryptedResponse(response) => {
                let dec = symmetric::decrypt(&response, key)?;
                let mut des = Deserializer::new(&dec[..]);
                let data = PrincipalMessageType::Response(Deserialize::deserialize(&mut des).map_err(|_| CryptoError::DecryptionError)?);
                Ok(Self { data, pubkey: enc.pubkey, id: enc.id })
            }
            _ => Err(CryptoError::EncryptionError),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UserMessage {
    pubkey: Vec<u8>
}

impl UserMessage {
    // The reason for the prefix is that I(@elichai) don't feel comfortable signing a plain public key.
    // Because ECDSA signature contains multiplication of curve points, so I'm not sure if signing on a valid curve point has any side effect.
    const PREFIX: &'static [u8; 19] = b"Enigma User Message";

    pub fn new(pubkey: PubKey) -> Self {
        let pubkey = pubkey.to_vec();
        Self { pubkey }
    }

    pub fn to_sign(&self) -> Vec<u8> {
        let to_sign = [&Self::PREFIX[..], &self.pubkey];
        hash::prepare_hash_multiple(&to_sign)
    }

    pub fn into_message(self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        let val = serde_json::to_value(self)
            .map_err(|_| SystemError(MessagingError {err: "Couldn't convert UserMesssage to Value".to_string()}))?;

        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_message(msg: &[u8]) -> Result<Self, EnclaveError> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)
            .map_err(|_| MessagingError { err: "Couldn't Deserialize UserMesssage"})?;;
        let msg: Self = serde_json::from_value(res)
            .map_err(|_| MessagingError { err: "Couldn't convert Value to UserMesssage"})?;
        if msg.pubkey.len() != 64 {
            return Err(MessagingError { err: "the pub key is not in the right length" })
        }
        Ok(msg)
    }

    pub fn get_pubkey(&self) -> PubKey {
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&self.pubkey[..]);
        pubkey
    }
}

#[cfg(debug_assertions)]
pub mod tests {
    use super::{PrincipalMessage, PrincipalMessageType};
    use enigma_crypto::hash::Sha256;
    use enigma_crypto::Encryption;

    pub fn test_to_message() {
        let req = get_request();

        assert_eq!(
            req.into_message().unwrap(),
            vec![131, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    pub fn test_from_message() {
        let msg = [132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97 , 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let req = get_request();
        assert_eq!(req, PrincipalMessage::from_message(&msg[..]).unwrap());
    }

    pub fn test_from_to_message() {
        let res = get_request();
        let msg = res.clone().into_message().unwrap();
        assert_eq!(PrincipalMessage::from_message(&msg).unwrap(), res);
    }

    pub fn test_encrypt_response() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 232, 197, 171, 8, 246, 211, 64, 243, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 240, 120, 203, 145, 26, 247, 128, 9, 133, 13, 233, 105, 131, 99, 154, 6, 136, 88, 112, 186, 196, 210, 190, 247, 96, 113, 70, 241, 163, 162, 242, 40, 207, 117, 148, 38, 133, 234, 100, 9, 6, 238, 251, 81, 181, 13, 139, 88, 187, 66, 195, 170, 245, 237, 230, 180, 217, 83, 84, 177, 247, 58, 173, 30, 222, 194, 21, 38, 221, 165, 196, 101, 20, 147, 103, 149, 3, 254, 248, 85, 234, 40, 48, 99, 143, 202, 4, 136, 97, 99, 71, 199, 145, 211, 106, 211, 10, 13, 212, 56, 205, 83, 38, 26, 172, 102, 146, 188, 97, 216, 195, 40, 65, 11, 156, 142, 206, 109, 224, 203, 26, 246, 51, 228, 203, 16, 143, 0, 224, 169, 119, 107, 133, 160, 125, 6, 57, 215, 241, 69, 189, 70, 30, 133, 117, 163, 77, 46, 166, 104, 204, 131, 247, 184, 139, 199, 104, 247, 72, 236, 187, 239, 245, 221, 81, 177, 206, 226, 9, 213, 226, 55, 119, 203, 44, 11, 47, 4, 152, 92, 202, 63, 68, 13, 34, 247, 12, 194, 170, 198, 35, 158, 95, 2, 22, 10, 128, 65, 254, 105, 194, 211, 14, 40, 248, 180, 84, 74, 147, 235, 226, 101, 81, 94, 57, 158, 3, 225, 145, 164, 141, 134, 157, 235, 199, 203, 180, 58, 131, 20, 41, 12, 202, 137, 49, 164, 239, 209, 182, 86, 146, 218, 12, 167, 211, 41, 216, 162, 24, 109, 136, 221, 234, 253, 193, 114, 145, 15, 188, 218, 48, 221, 247, 157, 210, 57, 238, 19, 209, 251, 102, 142, 100, 57, 221, 85, 38, 88, 191, 169, 128, 230, 8, 181, 156, 210, 190, 118, 13, 68, 47, 138, 4, 130, 174, 77, 76, 232, 70, 181, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = PrincipalMessageType::EncryptedResponse(enc);
        assert_eq!(enc_response, encrypt(response));
    }

    pub fn test_decrypt_reponse() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 232, 197, 171, 8, 246, 211, 64, 243, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 240, 120, 203, 145, 26, 247, 128, 9, 133, 13, 233, 105, 131, 99, 154, 6, 136, 88, 112, 186, 196, 210, 190, 247, 96, 113, 70, 241, 163, 162, 242, 40, 207, 117, 148, 38, 133, 234, 100, 9, 6, 238, 251, 81, 181, 13, 139, 88, 187, 66, 195, 170, 245, 237, 230, 180, 217, 83, 84, 177, 247, 58, 173, 30, 222, 194, 21, 38, 221, 165, 196, 101, 20, 147, 103, 149, 3, 254, 248, 85, 234, 40, 48, 99, 143, 202, 4, 136, 97, 99, 71, 199, 145, 211, 106, 211, 10, 13, 212, 56, 205, 83, 38, 26, 172, 102, 146, 188, 97, 216, 195, 40, 65, 11, 156, 142, 206, 109, 224, 203, 26, 246, 51, 228, 203, 16, 143, 0, 224, 169, 119, 107, 133, 160, 125, 6, 57, 215, 241, 69, 189, 70, 30, 133, 117, 163, 77, 46, 166, 104, 204, 131, 247, 184, 139, 199, 104, 247, 72, 236, 187, 239, 245, 221, 81, 177, 206, 226, 9, 213, 226, 55, 119, 203, 44, 11, 47, 4, 152, 92, 202, 63, 68, 13, 34, 247, 12, 194, 170, 198, 35, 158, 95, 2, 22, 10, 128, 65, 254, 105, 194, 211, 14, 40, 248, 180, 84, 74, 147, 235, 226, 101, 81, 94, 57, 158, 3, 225, 145, 164, 141, 134, 157, 235, 199, 203, 180, 58, 131, 20, 41, 12, 202, 137, 49, 164, 239, 209, 182, 86, 146, 218, 12, 167, 211, 41, 216, 162, 24, 109, 136, 221, 234, 253, 193, 114, 145, 15, 188, 218, 48, 221, 247, 157, 210, 57, 238, 19, 209, 251, 102, 142, 100, 57, 221, 85, 38, 88, 191, 169, 128, 230, 8, 181, 156, 210, 190, 118, 13, 68, 47, 138, 4, 130, 174, 77, 76, 232, 70, 181, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = PrincipalMessageType::EncryptedResponse(enc);
        assert_eq!(response, decrypt(enc_response));
    }

    pub fn test_encrypt_decrypt_response() {
        let res = get_response();
        let enc = encrypt(res.clone());
        assert_eq!(res, decrypt(enc))
    }

    fn get_request() -> PrincipalMessage {
        let data = PrincipalMessageType::Request(None);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        PrincipalMessage::new_id(data, id, [0u8; 64])
    }

    fn get_response() -> PrincipalMessage {
        let data = PrincipalMessageType::Response(vec![
            ([0u8; 32].into(), [1u8; 32]),
            ([1u8; 32].into(), [2u8; 32]),
            ([2u8; 32].into(), [3u8; 32]),
            ([3u8; 32].into(), [4u8; 32]),
            ([4u8; 32].into(), [5u8; 32]),
        ]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        PrincipalMessage::new_id(data, id, [0u8; 64])
    }

    fn encrypt(msg: PrincipalMessage) -> PrincipalMessage {
        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        msg.encrypt_with_nonce(&key, Some(iv)).unwrap()
    }

    fn decrypt(msg: PrincipalMessage) -> PrincipalMessage {
        let key = b"EnigmaMPC".sha256();
        PrincipalMessage::decrypt(msg, &key).unwrap()
    }

}
