use core::ops::{Deref, DerefMut};
use rustc_hex::{FromHex, FromHexError};
use arrayvec::ArrayVec;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Hash256([u8; 32]);


impl Hash256 {
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }

    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        if hex.len() != 64 {
            return Err(FromHexError::InvalidHexLength);
        }
        let hex_vec: ArrayVec<[u8; 32]> = hex.from_hex()?;
        let mut result = Self::default();
        result.copy_from_slice(&hex_vec);
        Ok(result)
    }
}


impl From<[u8; 32]> for Hash256 {
    fn from(arr: [u8; 32]) -> Self {
        Hash256(arr)
    }
}

impl Into<[u8; 32]> for Hash256 {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

impl Deref for Hash256 {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl DerefMut for Hash256 {
    fn deref_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Hash256 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

use crate::serde::de::{SeqAccess, Error};
use core::fmt::{self, Formatter};
use crate::serde::{Serialize, Deserialize, Serializer, Deserializer, de::Visitor};

impl Serialize for Hash256 {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error> where S: Serializer {
        Serializer::serialize_newtype_struct(ser, "Hash256", &self.0)
    }
}

struct Hash256Visitor;

impl<'de> Visitor<'de> for Hash256Visitor {
    type Value = Hash256;
    fn expecting(&self, fmt: &mut Formatter) -> fmt::Result {
        fmt.write_str("tuple struct Hash256")
    }

    fn visit_newtype_struct<E>(self, err: E) -> Result<Self::Value, E::Error> where E: Deserializer<'de>, {

        match <[u8; 32] as Deserialize>::deserialize(err) {
            Ok(field) => Ok(Hash256(field)),
            Err(err) => Err(err),
        }
    }

    fn visit_seq<A>(self, mut seq: A ) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
        match seq.next_element::<[u8; 32]>() {
            Ok(v) => match v {
                Some(field) => Ok(Hash256(field)),
                None => Err(Error::invalid_length(0, &"tuple struct Hash256 with 1 element" )),
            },
            Err(err) => Err(err)
        }
    }
}


impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D>(des: D) -> Result<Self, D::Error> where D: Deserializer<'de>, {
        des.deserialize_newtype_struct("Hash256", Hash256Visitor)
    }
}

#[cfg(test)]
mod test {
    use super::Hash256;
    #[test]
    fn test_hex_succeed() {
        let a = "0101010101010101010101010101010101010101010101010101010101010101";
        Hash256::from_hex(&a).unwrap();
    }

    #[should_panic]
    #[test]
    fn test_hex_long() {
        let a = "02020202020202020202020202020202020202020202020202020202020202020202024444020202020202";
        Hash256::from_hex(&a).unwrap();
    }
}