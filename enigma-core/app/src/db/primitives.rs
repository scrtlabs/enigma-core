use enigma_types::ContractAddress;
use failure::Error;
use hex::{FromHex, ToHex};
use std::str;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Array32u8(pub [u8; 32]);
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct VecKey(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct DeltaKey {
    pub contract_address: ContractAddress,
    pub key_type: Stype,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Delta {
    pub key: DeltaKey,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum Stype {
    Delta(u32),
    State,
    ByteCode,
}

impl Stype {
    pub fn unwrap_delta(self) -> u32 {
        match self {
            Stype::Delta(val) => val,
            _ => panic!("called `Stype::unwrap()` on a non `Delta` value"),
        }
    }
}

use std::fmt::Debug;
pub trait SplitKey: Debug { // The Debug is added for Debugging :), So if it ever brings up problems it can be removed.
    // as_split should get self and divide it up into two components
    // as a tuple (&str, &[u8]) and send it into a function,
    // something in this order: F(&str, &[u8]).
    //
    // we use this syntax, because It's impossible to
    // return a variable that is not owned by no one.
    fn as_split<T, F: FnMut(&str, &[u8]) -> T>(&self, f: F) -> T;

    // returns the split values back into the shape of the struct.
    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error>
    where Self: Sized;
}

impl Default for Stype {
    fn default() -> Self { Stype::State }
}

impl DeltaKey {
    pub fn new(contract_address: ContractAddress, key_type: Stype) -> DeltaKey { DeltaKey { contract_address, key_type } }
}

impl SplitKey for DeltaKey {
    fn as_split<T, F: FnMut(&str, &[u8]) -> T>(&self, mut f: F) -> T {
        // converts the [u8; 32] to a str.
        let cf = &self.contract_address.to_hex();
        let mut key = Vec::new();
        match &self.key_type {
            Stype::Delta(num) => {
                key.push(1); //type
                             // TODO: think of a better way to handle the possibility of error here.
                key.extend_from_slice(&num.to_be_bytes());
            }
            Stype::State => key.push(2),    //type
            Stype::ByteCode => key.push(3), //type
        }
        f(&cf, &key)
    }

    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error> {
        let key_type = match _key_type[0] {
            1 => {
                let mut be_bytes = [0u8; 4];
                be_bytes.copy_from_slice(&_key_type[1..]);
                Stype::Delta(u32::from_be_bytes(be_bytes))
            },
            2 => Stype::State,
            3 => Stype::ByteCode,
            _ => bail!("Failed parsing the Key, key does not contain a correct index"),
        };
        // if the address is not a correct hex then it not a correct address.
        let contract_address = ContractAddress::from_hex(&_hash)?;
        Ok(DeltaKey { contract_address, key_type })
    }
}

impl SplitKey for Array32u8 {
    fn as_split<T, F: FnMut(&str, &[u8]) -> T>(&self, mut f: F) -> T { f(&self.0.to_hex(), &[2]) }

    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error> {
        let hex: Vec<u8> = _hash.from_hex()?;
        if hex.len() != 32 { bail!("Wrong length"); }
        let mut result = [0u8; 32];
        result.copy_from_slice(&hex);
        Ok(Array32u8(result))
    }
}

#[cfg(test)]
mod tests {
    use db::primitives::*;
    use hex::ToHex;

    #[test]
    fn test_deltakey_from_split() {
        let accepted_address: [u8; 32] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let accepted_key: [u8; 5] = [1, 0, 8, 73, 39];
        let contract_address = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205].into();
        let key_type = Stype::Delta(543_015);
        let from = DeltaKey::from_split(&accepted_address.to_hex(), &accepted_key).unwrap();
        let orig_del = DeltaKey { contract_address, key_type };
        assert_eq!(from, orig_del);
    }

    #[test]
    fn test_deltakey_as_split() {
        let expected_address: &str = &[181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162].to_hex();
        let expected_key: &[u8; 5] = &[1, 1, 69, 200, 177];
        let contract_address = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162].into();
        let key_type: Stype = Stype::Delta(21_350_577);
        let del = DeltaKey { contract_address, key_type };
        del.as_split(|contract_address, key| {
            assert_eq!(contract_address, expected_address);
            assert_eq!(key, expected_key);
        });
    }
}
