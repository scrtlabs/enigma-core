use db_key::Key;
use byteorder::{WriteBytesExt, BigEndian, ByteOrder};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Array32u8 ( pub [u8; 32] );
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct VecKey ( pub Vec<u8> );

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct DeltaKey {
    hash: [u8; 32],
    n: Option<u32>
}

impl DeltaKey {
    pub fn new(hash: [u8; 32], n: Option<u32>) -> DeltaKey {
        DeltaKey { hash, n }
    }
}

impl Key for DeltaKey {
    fn from_u8(key: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&key[..32]);
        let mut n = None;

        if key.len() > 32 {
            n = Some( BigEndian::read_u32(&key[32..]) );
        }
        DeltaKey { hash, n }
    }

    fn as_slice< T, F: Fn(&[u8]) -> T > (&self, f: F) -> T {
        let mut slice = Vec::new();
        slice.extend_from_slice(&self.hash);
        if self.n.is_some() {
            // TODO: think of a better way to handle the possibility of error here.
            slice.write_u32::<BigEndian>(self.n.unwrap()).unwrap();
        }
        f(&slice[..])
    }
}


impl Key for Array32u8 {
    fn from_u8(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut bits = [0u8; 32];
        bits.clone_from_slice(key);
        Array32u8 ( bits )
    }
    fn as_slice<T, F: Fn(&[u8]) -> T> (&self, f: F) -> T {
        f(&self.0)
    }
}

impl Key for VecKey {
    fn from_u8(key: &[u8]) -> Self {
        VecKey ( key.to_vec() )
    }
    fn as_slice<T, F: Fn(&[u8]) -> T> (&self, f: F) -> T {
        f(&self.0[..])
    }
}

#[cfg(test)]
mod tests {
    use db::primitives::*;

    #[test]
    fn test_deltakey_from_u8() {
        let slice: [u8; 36] = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205, 0, 8, 73, 39];
        let hash = [205, 189, 133, 79, 16, 70, 59, 246, 123, 227, 66, 64, 244, 188, 188, 147, 233, 252, 213, 133, 44, 157, 173, 141, 50, 93, 40, 130, 44, 99, 43, 205];
        let n = Some( 543015 );
        assert_eq!(DeltaKey::from_u8(&slice), DeltaKey { hash, n });
    }

    #[test]
    fn test_deltakey_as_slice() {
        let slice = vec![181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162, 1, 69, 200, 177];
        let hash = [181, 71, 210, 141, 65, 214, 242, 119, 127, 212, 100, 4, 19, 131, 252, 56, 173, 224, 167, 158, 196, 65, 19, 33, 251, 198, 129, 58, 247, 127, 88, 162];
        let n: Option<u32> = Some( 21350577 );
        let del = DeltaKey { hash, n };
        del.as_slice( | x | { assert_eq!(x.to_vec(), slice); } );
    }
}