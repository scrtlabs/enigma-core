use std::clone::Clone;

use ethereum_types::{H160, H256};
use failure::Error;
use rmp_serde::Deserializer;
use serde::Deserialize;

use enigma_crypto::hash::Keccak256;
use enigma_crypto::KeyPair;
use enigma_types::ContractAddress;

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub enum PrincipalMessageType {
    Request(Option<Vec<ContractAddress>>),
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
pub struct PrincipalMessage {
    prefix: [u8; 14],
    pub data: PrincipalMessageType,
    pubkey: Vec<u8>,
    id: [u8; 12],
}

pub struct PrincipalMessageReader {
    request: Vec<u8>,
    principal_message: PrincipalMessage,
}

impl PrincipalMessageReader {
    pub fn new(request: Vec<u8>) -> Result<Self, Error> {
        let principal_message = Self::deserialize(&request)?;
        Ok(PrincipalMessageReader { request, principal_message })
    }

    #[logfn(DEBUG)]
    fn deserialize(msg: &[u8]) -> Result<PrincipalMessage, Error> {
        let mut des = Deserializer::new(&msg[..]);
        let res: serde_json::Value = Deserialize::deserialize(&mut des)?;
        println!("The JSON message: {:?}", serde_json::to_string_pretty(&res)?);
        println!("The deserialized message: {:?}", res);
        let msg: PrincipalMessage = serde_json::from_value(res).unwrap();
        Ok(msg)
    }

    #[logfn(DEBUG)]
    pub fn get_signing_address(&self, sig: [u8; 65]) -> Result<H160, Error> {
        let recovered = KeyPair::recover(&self.request, sig)?;
        let mut buf = [0u8; 20];
        buf.copy_from_slice(&recovered.keccak256()[12..32]);
        let addr = H160(buf);
        println!("Recovered signer address from the message signature: {:?}", addr);
        Ok(addr)
    }

    fn get_data(&self) -> Result<Option<Vec<ContractAddress>>, Error> {
        let data = match self.principal_message.data.clone() {
            PrincipalMessageType::Request(data) => data,
            _ => bail!("Invalid Principal message request"),
        };
        Ok(data)
    }

    pub fn get_contract_addresses(&self) -> Result<Option<Vec<H256>>, Error> {
        let data = match self.get_data()? {
            Some(addrs) => Some(addrs.into_iter().map(|a| H256(a.into())).collect()),
            None => None,
        };
        Ok(data)
    }
}

#[cfg(test)]
pub mod test {
    use rustc_hex::{FromHex, ToHex};

    use super::*;

    pub const WORKER_SIGN_ADDRESS: [u8; 20] = [95, 53, 26, 193, 96, 206, 55, 206, 15, 120, 191, 101, 13, 44, 28, 237, 80, 151, 54, 182];
    pub(crate) fn sign_message(msg: &Vec<u8>) -> Result<[u8; 65], Error> {
        let pkey = "79191a46ad1ed7a15e2bf64264c4b41fe6167ea887a5f7de82f52be073539730".from_hex()?;
        let mut pkey_slice: [u8; 32] = [0; 32];
        pkey_slice.copy_from_slice(&pkey);
        let key_pair = KeyPair::from_slice(&pkey_slice).unwrap();
        let sig = key_pair.sign(&msg).unwrap();
        Ok(sig)
    }

    #[test]
    pub fn test_get_contract_addresses_empty() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let reader = PrincipalMessageReader::new(msg).unwrap();
        let addrs = reader.get_contract_addresses().unwrap();
        println!("The contract addresses: {:?}", addrs);
        assert_eq!(addrs, None);
    }

    #[test]
    pub fn test_get_signing_address() {
        let msg = vec![132, 164, 100, 97, 116, 97, 129, 167, 82, 101, 113, 117, 101, 115, 116, 192, 162, 105, 100, 156, 75, 52, 85, 204, 160, 204, 254, 16, 9, 204, 130, 50, 81, 204, 252, 204, 231, 166, 112, 114, 101, 102, 105, 120, 158, 69, 110, 105, 103, 109, 97, 32, 77, 101, 115, 115, 97, 103, 101, 166, 112, 117, 98, 107, 101, 121, 220, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let sig = sign_message(&msg).unwrap();
        let reader = PrincipalMessageReader::new(msg).unwrap();
        let worker_address = reader.get_signing_address(sig).unwrap();
        println!("The worker address: {:?}", worker_address);
        assert_eq!(format!("{:?}", worker_address), format!("0x{}", WORKER_SIGN_ADDRESS.to_hex()));
    }
}
