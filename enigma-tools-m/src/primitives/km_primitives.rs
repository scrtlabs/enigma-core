//! # Key Management Primitives.
//! This module contains the code for the structs and enums that are used in communication with the Key Management Node
//! And the User for exchanging DH keys.

use crate::common::errors::ToolsError::{self, MessagingError};
use crate::localstd::vec::Vec;
use crate::rmp_serde::{Deserializer, Serializer};
use crate::serde::{Deserialize, Serialize};
use crate::serde_json;
use enigma_crypto::{rand, symmetric, CryptoError, Encryption, hash};
use enigma_types::{ContractAddress, DhKey, PubKey, StateKey};

/// A Message ID type, used to identify each message to the response.
pub type MsgID = [u8; 12];

/// the size of the publicKey in the network.
pub const PUB_KEY_SIZE: usize = 64;

/// verifies if the publicKey is in the expected size.
/// inputs: pubkey: &[u8]
pub fn verify_key_size(pubkey: &[u8]) -> Result<(), ToolsError> {
    if pubkey.len() != PUB_KEY_SIZE {
        return Err(MessagingError { err: "the pub key is not of the right length" })
    }
    Ok(())
}

/// An enum used to differentiate between `Request` and `Response`.
/// and between Response before and after encryption
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(crate = "crate::serde")]
pub enum PrincipalMessageType {
    /// A Response from the KM node, containing a list of (Address, Key) tuples.
    Response(Vec<(ContractAddress, StateKey)>),
    /// A Request for the KM node.
    // todo: split PrincipalMessage into PrincipalRequestMessage and PrincipalResponseMessage
    // todo: in order to remove redundant fields (data is not needed for ptt request)
    Request,
    /// The same as `Response` but this is after encryption.
    EncryptedResponse(Vec<u8>),
}

/// The Message struct used to communicate between a worker and the Key Management Node.
/// this struct contains the data(request/response) the DH pubkey and the MsgID.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(crate = "crate::serde")]
pub struct PrincipalMessage {
    /// The data of the message.
    ///
    /// This can be either Request/Response or an Encrypted Response.
    pub data: PrincipalMessageType,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) id: MsgID,
}

impl PrincipalMessage {
    /// This will create a new Message with a random MsgID.
    pub fn new(data: PrincipalMessageType, pubkey: PubKey) -> Result<Self, CryptoError> {
        let mut id = [0u8; 12];
        rand::random(&mut id)?;
        let pubkey = pubkey.to_vec();
        Ok(Self { data, pubkey, id })
    }

    /// This should be used only by the KeyManagement node to create a response that will contain the same ID
    /// as the request.
    pub fn new_id(data: PrincipalMessageType, id: [u8; 12], pubkey: PubKey) -> Self {
        let pubkey = pubkey.to_vec();
        Self { data, pubkey, id }
    }

    /// This should serialize the struct for it to be signed, using [`enigma_crypto::hash::prepare_hash_multiple()`]
    pub fn to_sign(&self) -> Result<Vec<u8>, ToolsError> {
        if self.is_response() {
            return Err(MessagingError { err: "can't serialize non encrypted response" });
        }
        let mut to_sign = Vec::with_capacity(3);
        match &self.data {
            PrincipalMessageType::EncryptedResponse(v) => to_sign.push(v.clone()),
            PrincipalMessageType::Request => (),
            PrincipalMessageType::Response(_) => unreachable!(), // This can't be reached because we check if it's a response before.
        }
        to_sign.push(self.pubkey.to_vec());
        to_sign.push(self.id.to_vec());
        Ok(hash::prepare_hash_multiple(&to_sign))
    }

    /// This will serialize the Message using MessagePack.
    pub fn into_message(self) -> Result<Vec<u8>, ToolsError> {
        if self.is_response() {
            return Err(MessagingError { err: "can't serialize non encrypted response" });
        }
        let mut buf = Vec::new();
        let val = serde_json::to_value(self).map_err(|_| MessagingError { err: "can't serialize the message" })?;
        val.serialize(&mut Serializer::new(&mut buf)).map_err(|_| MessagingError { err: "can't serialize the message" })?;
        Ok(buf)
    }

    /// This will deserialize the Message using MessagePack.
    pub fn from_message(msg: &[u8]) -> Result<Self, ToolsError> {
        let mut des = Deserializer::new(msg);
        let res: serde_json::Value =
            Deserialize::deserialize(&mut des).map_err(|_| MessagingError { err: "can't deserialize the message" })?;
        let msg: Self = serde_json::from_value(res).map_err(|_| MessagingError { err: "can't deserialize the message" })?;
        verify_key_size(&msg.pubkey)?;
        Ok(msg)
    }

    /// Will return the DH public key from the message.
    pub fn get_pubkey(&self) -> PubKey {
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&self.pubkey[..]);
        pubkey
    }

    /// Will return the MsgID
    pub fn get_id(&self) -> MsgID { self.id }

    /// Check if the Message's data is a Request or not
    pub fn is_request(&self) -> bool {
        if let PrincipalMessageType::Request = self.data {
            true
        } else {
            false
        }
    }

    /// Check if the Message's data is a Response or not
    pub fn is_response(&self) -> bool {
        if let PrincipalMessageType::Response(_) = self.data {
            true
        } else {
            false
        }
    }

    /// Check if the Message's data is an Encrypted Response or not
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
            _ => Err(CryptoError::EncryptionError),
        }
    }

    fn decrypt(enc: Self, key: &DhKey) -> Result<Self, CryptoError> {
        match &enc.data {
            PrincipalMessageType::EncryptedResponse(response) => {
                let dec = symmetric::decrypt(&response, key)?;
                let mut des = Deserializer::new(&dec[..]);
                let data =
                    PrincipalMessageType::Response(Deserialize::deserialize(&mut des).map_err(|_| CryptoError::DecryptionError)?);
                Ok(Self { data, pubkey: enc.pubkey, id: enc.id })
            }
            _ => Err(CryptoError::EncryptionError),
        }
    }
}

/// A struct to represent the UserMessage for the key exchange.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(crate = "crate::serde")]
pub struct UserMessage {
    pub(crate) pubkey: Vec<u8>,
}

impl UserMessage {
    // The reason for the prefix is that I(@elichai) don't feel comfortable signing a plain public key.
    // Because ECDSA signature contains multiplication of curve points, so I'm not sure if signing on a valid curve point has any side effect.
    const PREFIX: &'static [u8; 19] = b"Enigma User Message";

    /// Generate a new UserMessage struct with the provided public key.
    pub fn new(pubkey: PubKey) -> Self {
        let pubkey = pubkey.to_vec();
        Self { pubkey }
    }

    /// This should serialize the struct for it to be signed, using [`enigma_crypto::hash::prepare_hash_multiple()`]
    /// it will add a prefix to the data, `b"Enigma User Message"`.
    pub fn to_sign(&self) -> Vec<u8> {
        let to_sign = [&Self::PREFIX[..], &self.pubkey];
        hash::prepare_hash_multiple(&to_sign)
    }

    /// This will serialize the Message using MessagePack.
    pub fn into_message(self) -> Result<Vec<u8>, ToolsError> {
        let mut buf = Vec::new();
        let val = serde_json::to_value(self).map_err(|_| MessagingError { err: "Couldn't convert UserMesssage to Value" })?;
        val.serialize(&mut Serializer::new(&mut buf)).map_err(|_| MessagingError { err: "Couldn't serialize UserMesssage" })?;;
        Ok(buf)
    }

    /// This will deserialize the Message using MessagePack.
    pub fn from_message(msg: &[u8]) -> Result<Self, ToolsError> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)
            .map_err(|_| MessagingError { err: "Couldn't Deserialize UserMesssage"})?;;
        let msg: Self = serde_json::from_value(res)
            .map_err(|_| MessagingError { err: "Couldn't convert Value to UserMesssage"})?;
        verify_key_size(&msg.pubkey)?;
        Ok(msg)
    }

    /// Will return the DH public key from the message.
    pub fn get_pubkey(&self) -> PubKey {
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&self.pubkey[..]);
        pubkey
    }
}

#[cfg(test)]
mod tests {
    use super::{PrincipalMessage, PrincipalMessageType};
    use enigma_crypto::hash::Sha256;
    use enigma_crypto::Encryption;

    #[test]
    fn test_to_message() {
        let req = get_request();

        assert_eq!(
            req.into_message().unwrap(),
            vec![131, 164, 100, 97, 116, 97, 167, 82, 101, 113, 117, 101, 115, 116, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
    }

    #[test]
    fn test_from_message() {
        let msg = [132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ];
        let req = get_request();
        assert_eq!(req, PrincipalMessage::from_message(&msg[..]).unwrap());
    }

    #[test]
    fn test_from_to_message() {
        let res = get_request();
        let msg = res.clone().into_message().unwrap();
        assert_eq!(PrincipalMessage::from_message(&msg).unwrap(), res);
    }

    #[test]
    fn test_encrypt_response() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 232, 197, 171, 8, 246, 211, 64, 243, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 240, 120, 203, 145, 26, 247, 128, 9, 133, 13, 233, 105, 131, 99, 154, 6, 136, 88, 112, 186, 196, 210, 190, 247, 96, 113, 70, 241, 163, 162, 242, 40, 207, 117, 148, 38, 133, 234, 100, 9, 6, 238, 251, 81, 181, 13, 139, 88, 187, 66, 195, 170, 245, 237, 230, 180, 217, 83, 84, 177, 247, 58, 173, 30, 222, 194, 21, 38, 221, 165, 196, 101, 20, 147, 103, 149, 3, 254, 248, 85, 234, 40, 48, 99, 143, 202, 4, 136, 97, 99, 71, 199, 145, 211, 106, 211, 10, 13, 212, 56, 205, 83, 38, 26, 172, 102, 146, 188, 97, 216, 195, 40, 65, 11, 156, 142, 206, 109, 224, 203, 26, 246, 51, 228, 203, 16, 143, 0, 224, 169, 119, 107, 133, 160, 125, 6, 57, 215, 241, 69, 189, 70, 30, 133, 117, 163, 77, 46, 166, 104, 204, 131, 247, 184, 139, 199, 104, 247, 72, 236, 187, 239, 245, 221, 81, 177, 206, 226, 9, 213, 226, 55, 119, 203, 44, 11, 47, 4, 152, 92, 202, 63, 68, 13, 34, 247, 12, 194, 170, 198, 35, 158, 95, 2, 22, 10, 128, 65, 254, 105, 194, 211, 14, 40, 248, 180, 84, 74, 147, 235, 226, 101, 81, 94, 57, 158, 3, 225, 145, 164, 141, 134, 157, 235, 199, 203, 180, 58, 131, 20, 41, 12, 202, 137, 49, 164, 239, 209, 182, 86, 146, 218, 12, 167, 211, 41, 216, 162, 24, 109, 136, 221, 234, 253, 193, 114, 145, 15, 188, 218, 48, 221, 247, 157, 210, 57, 238, 19, 209, 251, 102, 142, 100, 57, 221, 85, 38, 88, 191, 169, 128, 230, 8, 181, 156, 210, 190, 118, 13, 68, 47, 138, 4, 130, 174, 77, 76, 232, 70, 181, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = PrincipalMessageType::EncryptedResponse(enc);
        assert_eq!(enc_response, encrypt(response));
    }

    #[test]
    fn test_decrypt_reponse() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 232, 197, 171, 8, 246, 211, 64, 243, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 240, 120, 203, 145, 26, 247, 128, 9, 133, 13, 233, 105, 131, 99, 154, 6, 136, 88, 112, 186, 196, 210, 190, 247, 96, 113, 70, 241, 163, 162, 242, 40, 207, 117, 148, 38, 133, 234, 100, 9, 6, 238, 251, 81, 181, 13, 139, 88, 187, 66, 195, 170, 245, 237, 230, 180, 217, 83, 84, 177, 247, 58, 173, 30, 222, 194, 21, 38, 221, 165, 196, 101, 20, 147, 103, 149, 3, 254, 248, 85, 234, 40, 48, 99, 143, 202, 4, 136, 97, 99, 71, 199, 145, 211, 106, 211, 10, 13, 212, 56, 205, 83, 38, 26, 172, 102, 146, 188, 97, 216, 195, 40, 65, 11, 156, 142, 206, 109, 224, 203, 26, 246, 51, 228, 203, 16, 143, 0, 224, 169, 119, 107, 133, 160, 125, 6, 57, 215, 241, 69, 189, 70, 30, 133, 117, 163, 77, 46, 166, 104, 204, 131, 247, 184, 139, 199, 104, 247, 72, 236, 187, 239, 245, 221, 81, 177, 206, 226, 9, 213, 226, 55, 119, 203, 44, 11, 47, 4, 152, 92, 202, 63, 68, 13, 34, 247, 12, 194, 170, 198, 35, 158, 95, 2, 22, 10, 128, 65, 254, 105, 194, 211, 14, 40, 248, 180, 84, 74, 147, 235, 226, 101, 81, 94, 57, 158, 3, 225, 145, 164, 141, 134, 157, 235, 199, 203, 180, 58, 131, 20, 41, 12, 202, 137, 49, 164, 239, 209, 182, 86, 146, 218, 12, 167, 211, 41, 216, 162, 24, 109, 136, 221, 234, 253, 193, 114, 145, 15, 188, 218, 48, 221, 247, 157, 210, 57, 238, 19, 209, 251, 102, 142, 100, 57, 221, 85, 38, 88, 191, 169, 128, 230, 8, 181, 156, 210, 190, 118, 13, 68, 47, 138, 4, 130, 174, 77, 76, 232, 70, 181, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = PrincipalMessageType::EncryptedResponse(enc);
        assert_eq!(response, decrypt(enc_response));
    }

    #[test]
    fn test_encrypt_decrypt_response() {
        let res = get_response();
        let enc = encrypt(res.clone());
        assert_eq!(res, decrypt(enc))
    }

    fn get_request() -> PrincipalMessage {
        let data = PrincipalMessageType::Request;
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
