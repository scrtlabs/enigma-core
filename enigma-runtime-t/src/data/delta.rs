use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_crypto::hash::Sha256;
use enigma_crypto::{symmetric, Encryption};
use enigma_types::{Hash256, ContractAddress, StateKey};
use json_patch;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StatePatch {
    pub patch: json_patch::Patch,
    pub previous_hash: Hash256,
    #[serde(skip)]
    pub contract_id: ContractAddress,
    #[serde(skip)]
    pub index: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EncryptedPatch {
    pub data: Vec<u8>,
    pub contract_id: ContractAddress,
    pub index: u32,
}

impl StatePatch {
    pub fn sha256_patch(&self) -> Result<Hash256, EnclaveError> {
        let mut buf = Vec::new();
        self.patch.serialize(&mut Serializer::new(&mut buf))?;
        Ok(buf.sha256())
    }
}

impl<'a> Encryption<&'a StateKey, EnclaveError, EncryptedPatch, [u8; 12]> for StatePatch {
    fn encrypt_with_nonce(self, key: &StateKey, _iv: Option<[u8; 12]>) -> Result<EncryptedPatch, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let data = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        let contract_id = self.contract_id;
        let index = self.index;
        Ok(EncryptedPatch { data, contract_id, index })
    }

    fn decrypt(enc: EncryptedPatch, key: &StateKey) -> Result<Self, EnclaveError> {
        let dec = symmetric::decrypt(&enc.data, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut back: Self = Deserialize::deserialize(&mut des)?;
        back.contract_id = enc.contract_id;
        back.index = enc.index;
        Ok(back)
    }
}
