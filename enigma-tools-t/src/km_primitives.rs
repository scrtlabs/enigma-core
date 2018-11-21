use crate::common::errors_t::EnclaveError;
use crate::cryptography_t::{symmetric, Encryption};
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use sgx_trts::trts::rsgx_read_rand;
use std::vec::Vec;

pub type StateKey = Vec<u8>;
pub type ContractAddress = [u8; 32];
pub type MsgID = [u8; 12];
pub type PubKey = [u8; 64];

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Response(Vec<(ContractAddress, StateKey)>),
    Request(Vec<ContractAddress>),
    EncryptedResponse(Vec<u8>),
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Message {
    #[doc(hidden)]
    prefix: [u8; 14],
    data: MessageType,
    pubkey: Vec<u8>,
    id: MsgID,
}

impl Message {
    const PREFIX: &'static [u8; 14] = b"Enigma Message";

    pub fn new(data: MessageType, pubkey: PubKey) -> Result<Message, EnclaveError> {
        let mut id = [0u8; 12];
        rsgx_read_rand(&mut id)?;
        let pubkey = pubkey.to_vec();
        let prefix = *Self::PREFIX;
        Ok(Message { data, pubkey, id, prefix })
    }

    pub fn new_id(data: MessageType, id: [u8; 12], pubkey: PubKey) -> Message {
        let pubkey = pubkey.to_vec();
        let prefix = *Self::PREFIX;
        Message { data, pubkey, id, prefix }
    }

    pub fn to_message(&self) -> Result<Vec<u8>, EnclaveError> {
        let mut buf = Vec::new();
        let val = serde_json::to_value(self.clone()).unwrap();
        val.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf)
    }

    pub fn from_message(msg: &[u8]) -> Result<Message, EnclaveError> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)?;
        let msg: Message = serde_json::from_value(res).unwrap();
        Ok(msg)
    }

    pub fn get_id(&self) -> MsgID { self.id }

    pub fn is_request(&self) -> bool { if let MessageType::Request(_) = self.data { true } else { false } }

    pub fn is_response(&self) -> bool { if let MessageType::Response(_) = self.data { true } else { false } }

    pub fn is_encrypted_response(&self) -> bool { if let MessageType::EncryptedResponse(_) = self.data { true } else { false } }
}

impl<'a> Encryption<&'a [u8], EnclaveError, Self, [u8; 12]> for Message {
    fn encrypt_with_nonce(self, key: &[u8], _iv: Option<[u8; 12]>) -> Result<Self, EnclaveError> {
        match self.data {
            MessageType::Response(response) => {
                let mut buf = Vec::new();
                response.serialize(&mut Serializer::new(&mut buf))?;
                let enc = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
                Ok(Self { prefix: self.prefix,
                          data: MessageType::EncryptedResponse(enc),
                          pubkey: self.pubkey,
                          id: self.id, })
            }
            _ => Err(EnclaveError::EncryptionError {}),
        }
    }

    fn decrypt(enc: Self, key: &[u8]) -> Result<Self, EnclaveError> {
        match &enc.data {
            MessageType::EncryptedResponse(response) => {
                let dec = symmetric::decrypt(&response, key)?;
                let mut des = Deserializer::new(&dec[..]);
                let data = MessageType::Response(Deserialize::deserialize(&mut des)?);
                Ok(Self { prefix: enc.prefix, data, pubkey: enc.pubkey, id: enc.id })
            }
            _ => Err(EnclaveError::EncryptionError {}),
        }
    }
}

pub mod tests {
    use super::{Message, MessageType};
    use crate::common::Sha256;
    use crate::cryptography_t::Encryption;

    pub fn test_to_message() {
        let res = get_request();
        assert_eq!(res.to_message().unwrap(), vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    pub fn test_from_message() {
        let msg = [132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 149, 220, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 220, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 220, 0, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 220, 0, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 220, 0, 32, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let data = MessageType::Request(vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];
        assert_eq!(Message::new_id(data, id, [0u8; 64]), Message::from_message(&msg[..]).unwrap());
    }

    pub fn test_from_to_message() {
        let res = get_request();
        let msg = res.to_message().unwrap();
        assert_eq!(Message::from_message(&msg[..]).unwrap(), res);
    }

    pub fn test_encrypt_response() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 167, 196, 137, 10, 101, 14, 65, 210, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 99, 165, 202, 176, 26, 101, 128, 10, 135, 158, 52, 104, 162, 96, 153, 5, 139, 91, 115, 185, 199, 209, 189, 244, 99, 114, 69, 242, 160, 161, 241, 43, 204, 118, 151, 37, 91, 232, 70, 9, 6, 238, 251, 81, 181, 156, 136, 88, 186, 210, 29, 168, 215, 236, 231, 181, 216, 82, 85, 176, 246, 59, 172, 31, 223, 195, 20, 39, 220, 164, 197, 244, 203, 144, 68, 148, 2, 255, 249, 84, 235, 41, 49, 98, 142, 91, 7, 136, 96, 243, 153, 197, 179, 213, 108, 213, 12, 11, 210, 62, 203, 85, 32, 28, 170, 96, 148, 100, 101, 252, 196, 47, 70, 12, 155, 137, 201, 106, 231, 204, 29, 241, 52, 227, 204, 128, 141, 1, 224, 92, 14, 204, 60, 120, 193, 190, 109, 72, 135, 205, 127, 107, 165, 106, 72, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = MessageType::EncryptedResponse(enc);
        assert_eq!(enc_response, encrypt(response));
    }

    pub fn test_decrypt_reponse() {
        let enc = vec![195, 38, 192, 74, 88, 16, 137, 135, 207, 55, 231, 118, 249, 61, 195, 224, 63, 196, 241, 106, 78, 168, 173, 219, 207, 22, 170, 96, 122, 179, 196, 113, 182, 144, 124, 131, 226, 167, 196, 137, 10, 101, 14, 65, 210, 184, 206, 230, 208, 207, 182, 72, 131, 6, 120, 95, 206, 187, 5, 93, 183, 180, 62, 183, 196, 11, 161, 203, 226, 45, 171, 108, 99, 165, 202, 176, 26, 101, 128, 10, 135, 158, 52, 104, 162, 96, 153, 5, 139, 91, 115, 185, 199, 209, 189, 244, 99, 114, 69, 242, 160, 161, 241, 43, 204, 118, 151, 37, 91, 232, 70, 9, 6, 238, 251, 81, 181, 156, 136, 88, 186, 210, 29, 168, 215, 236, 231, 181, 216, 82, 85, 176, 246, 59, 172, 31, 223, 195, 20, 39, 220, 164, 197, 244, 203, 144, 68, 148, 2, 255, 249, 84, 235, 41, 49, 98, 142, 91, 7, 136, 96, 243, 153, 197, 179, 213, 108, 213, 12, 11, 210, 62, 203, 85, 32, 28, 170, 96, 148, 100, 101, 252, 196, 47, 70, 12, 155, 137, 201, 106, 231, 204, 29, 241, 52, 227, 204, 128, 141, 1, 224, 92, 14, 204, 60, 120, 193, 190, 109, 72, 135, 205, 127, 107, 165, 106, 72, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let response = get_response();
        let mut enc_response = response.clone();
        enc_response.data = MessageType::EncryptedResponse(enc);
        assert_eq!(response, decrypt(enc_response));
    }

    pub fn test_encrypt_decrypt_response() {
        let res = get_response();
        let enc = encrypt(res.clone());
        assert_eq!(res, decrypt(enc))
    }

    fn get_request() -> Message {
        let data = MessageType::Request(vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        Message::new_id(data, id, [0u8; 64])
    }

    fn get_response() -> Message {
        let data = MessageType::Response(vec![([0u8; 32], vec![1, 2, 3]),
                                              ([1u8; 32], vec![1, 2, 3]),
                                              ([2u8; 32], vec![1, 2, 3]),
                                              ([3u8; 32], vec![1, 2, 3]),
                                              ([4u8; 32], vec![1, 2, 3])]);
        let id = [75, 52, 85, 160, 254, 16, 9, 130, 50, 81, 252, 231];

        Message::new_id(data, id, [0u8; 64])
    }

    fn encrypt(msg: Message) -> Message {
        let key = b"EnigmaMPC".sha256();
        let iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        msg.encrypt_with_nonce(&key, Some(iv)).unwrap()
    }

    fn decrypt(msg: Message) -> Message {
        let key = b"EnigmaMPC".sha256();
        Message::decrypt(msg, &key[..]).unwrap()
    }

}
