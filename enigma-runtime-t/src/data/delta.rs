use enigma_tools_t::common::errors_t::EnclaveError;
use enigma_crypto::hash::Keccak256;
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
    pub contract_address: ContractAddress,
    #[serde(skip)]
    pub index: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct EncryptedPatch {
    pub data: Vec<u8>,
    pub contract_address: ContractAddress,
    pub index: u32,
}

impl EncryptedPatch {
    pub fn keccak256_patch(&self) -> Hash256 {
        self.data.keccak256()
    }
}

impl<'a> Encryption<&'a StateKey, EnclaveError, EncryptedPatch, [u8; 12]> for StatePatch {
    fn encrypt_with_nonce(self, key: &StateKey, _iv: Option<[u8; 12]>) -> Result<EncryptedPatch, EnclaveError> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf))?;
        let data = symmetric::encrypt_with_nonce(&buf, key, _iv)?;
        let contract_address = self.contract_address;
        let index = self.index;
        Ok(EncryptedPatch { data, contract_address, index })
    }

    fn decrypt(enc: EncryptedPatch, key: &StateKey) -> Result<Self, EnclaveError> {
        let dec = symmetric::decrypt(&enc.data, key)?;
        let mut des = Deserializer::new(&dec[..]);
        let mut back: Self = Deserialize::deserialize(&mut des)?;
        back.contract_address = enc.contract_address;
        back.index = enc.index;
        Ok(back)
    }
}
