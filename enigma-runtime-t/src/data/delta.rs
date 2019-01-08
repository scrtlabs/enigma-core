use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_tools_t::common::Sha256;
use enigma_tools_t::cryptography_t::{symmetric, Encryption};
use json_patch;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StatePatch {
    pub patch: json_patch::Patch,
    pub previous_hash: [u8; 32],
    #[serde(skip)]
    pub contract_id: [u8; 32],
    #[serde(skip)]
    pub index: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EncryptedPatch {
    pub data: Vec<u8>,
    pub contract_id: [u8; 32],
    pub index: u32,
}

impl StatePatch {
    pub fn sha256_patch(&self) -> Result<[u8; 32], EnclaveError> {
        let mut buf = Vec::new();
        self.patch.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf.sha256())
    }
}

impl<'a> Encryption<&'a [u8; 32], EnclaveError, EncryptedPatch, [u8; 12]> for StatePatch {
    fn encrypt_with_nonce(self, key: &[u8; 32], _iv: Option<[u8; 12]>) -> Result<EncryptedPatch, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let data = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        let contract_id = self.contract_id;
        let index = self.index;
        Ok(EncryptedPatch { data, contract_id, index })
    }

    fn decrypt(enc: EncryptedPatch, key: &[u8; 32]) -> Result<Self, EnclaveError> {
        let dec = symmetric::decrypt(&enc.data, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut back: Self = Deserialize::deserialize(&mut des).unwrap();
        back.contract_id = enc.contract_id;
        back.index = enc.index;
        Ok(back)
    }
}
