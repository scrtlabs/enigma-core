
use ring::digest;
use crate::localstd::{string::String, vec::Vec, mem};
use crate::byteorder::{BigEndian, WriteBytesExt};
use crate::CryptoError;
use tiny_keccak::Keccak;
use rustc_hex::ToHex;


/// Takes a list of variables and concat them together with lengths in between.
/// What this does is appends the length of the messages before each message and makes one big slice from all of them.
/// e.g.: `S(H(len(a)+a, len(b)+b...))`
/// # Examples
/// ```
/// use enigma_crypto::hashing;
/// let msg = b"sign";
/// let msg2 = b"this";
/// let ready = hashing::prepare_hash_multiple(&[msg, msg2]);
/// ```
pub fn prepare_hash_multiple(messages: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let res: Result<Vec<_>, CryptoError> = messages
        .into_iter()
        .map(|s| {
            let len = s.len();
            let size = mem::size_of_val(&len);
            let mut tmp = Vec::with_capacity(len + size);
            tmp.write_uint::<BigEndian>(len as u64, size)?;
            tmp.extend_from_slice(s);
            Ok(tmp)
        })
        .collect();
    Ok(res?.into_iter().flatten().collect())
}



// Hash a byte array into keccak256.
pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

pub trait Sha256<T> {
    fn sha256(&self) -> T where T: Sized;
}

pub trait EthereumAddress<T> {
    fn address(&self) -> T where T: Sized;
}


impl EthereumAddress<String> for [u8; 64] {
    // TODO: Maybe add a checksum address
    fn address(&self) -> String {
        let mut result: String = String::from("0x");
        result.push_str(&self.keccak256()[12..32].to_hex::<String>());
        result
    }
}

impl Keccak256<[u8; 32]> for [u8] {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self);
        keccak.finalize(&mut result);
        result
    }
}

impl Sha256<[u8; 32]> for [u8] {
    fn sha256(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        let hash = digest::digest(&digest::SHA256, self);
        result.copy_from_slice(hash.as_ref());
        result
    }
}