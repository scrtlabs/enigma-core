use byteorder::{WriteBytesExt, BigEndian, ByteOrder};
use hex::{ToHex, FromHex};
use std::str;
use failure::Error;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Array32u8 ( pub [u8; 32] );
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct VecKey ( pub Vec<u8> );

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct DeltaKey {
    pub hash: [u8; 32],
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

pub trait SplitKey {
    // as_split should get self and divide it up into two components
    // as a tuple (&str, &[u8]) and send it into a function,
    // something in this order: F(&str, &[u8]).
    //
    // we use this syntax, because we are unable to
    // return a variable that is not owned by no one.
    fn as_split< T, F: FnMut(&str, &[u8]) -> T > (&self, f: F) -> T;

    // returns the split values back into the shape of the struct.
    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error> where Self: Sized;
}

impl Default for Stype {
    fn default() -> Self {
        Stype::State
    }
}

impl DeltaKey {
    pub fn new(hash: [u8; 32], key_type: Stype) -> DeltaKey {
        DeltaKey { hash, key_type }
    }
}

impl SplitKey for DeltaKey {

    fn as_split< T, F: FnMut(&str, &[u8]) -> T > (&self, mut f: F) -> T {
        // converts the [u8; 32] to a str.
        let cf = &self.hash.to_hex();
        let mut key = Vec::new();
        match &self.key_type {
            Stype::Delta(num) => {
                key.push(1);    //type
                // TODO: think of a better way to handle the possibility of error here.
                key.write_u32::<BigEndian>(*num).unwrap();
            },
            Stype::State =>  key.push(2),    //type
            Stype::ByteCode => key.push(3),  //type
        }
        f(&cf, &key)
    }

    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error> {
        let key_type = match _key_type[0] {
            1 => Stype::Delta(BigEndian::read_u32(&_key_type[1..])),
            2 => Stype::State,
            3 => Stype::ByteCode,
            _ => bail!("Failed parsing the Key, key does not contain a correct index")
        };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&_hash.from_hex()?[..]);
        Ok( DeltaKey{hash, key_type} )
    }
}

impl SplitKey for Array32u8 {

    fn as_split< T, F: FnMut(&str, &[u8]) -> T > (&self, mut f: F) -> T { f(&self.0.to_hex(), &[2])}

    fn from_split(_hash: &str, _key_type: &[u8]) -> Result<Self, Error> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&_hash.from_hex()?[..]);
        Ok(Array32u8(arr))
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
        let hash = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let key_type = Stype::Delta( 543015 );
        let from = DeltaKey::from_split(&accepted_address.to_hex(), &accepted_key).unwrap();
        let orig_del = DeltaKey { hash, key_type };
        assert_eq!(from , orig_del) ;
    }

    #[test]
    fn test_deltakey_as_split() {
        let expected_address: &str = &[181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162].to_hex();
        let expected_key: &[u8; 5] = &[1, 1, 69, 200, 177];
        let hash = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162];
        let key_type: Stype = Stype::Delta( 21350577 );
        let del = DeltaKey { hash, key_type };
        del.as_split( | hash, key | {
            assert_eq!(hash, expected_address);
            assert_eq!(key, expected_key)
        });
    }
}
