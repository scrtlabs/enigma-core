use json_patch;
use enigma_tools_t::cryptography_t::{Encryption, symmetric};
use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::utils_t::Sha256;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::vec::Vec;


#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StatePatch ( pub json_patch::Patch ); // TODO: the index should be here?

//pub type EncryptedPatch = Vec<u8>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EncryptedPatch {
    pub data: Vec<u8>,
    pub hash: [u8; 32],
    pub index: u32,
}

impl<'a> Encryption<&'a [u8], EnclaveError, EncryptedPatch, [u8; 12]> for StatePatch {
    fn encrypt(&self, key: &[u8]) -> Result<EncryptedPatch, EnclaveError> {
        self.encrypt_with_nonce(key, None)
    }

    fn encrypt_with_nonce(&self, key: &[u8], _iv: Option< [u8; 12] >) -> Result<EncryptedPatch, EnclaveError> {
        let mut buf = Vec::new();
        self.0.serialize(&mut Serializer::new(&mut buf))?;
        let data = symmetric::encrypt_with_nonce(&buf, &key[..], _iv)?;
        let hash = data.sha256();
        let index = 99; // TODO: determine who stores the index
        Ok( EncryptedPatch { data, hash, index } )
    }

    fn decrypt(enc: &EncryptedPatch, key: &[u8]) -> Result<StatePatch, EnclaveError> {
        let dec = symmetric::decrypt(&enc.data, &key[..])?;
        let mut des = Deserializer::new(&dec[..]);
        let back: json_patch::Patch = Deserialize::deserialize(&mut des).unwrap();
        Ok( StatePatch(back) )
    }
}