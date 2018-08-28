use db_key::Key;

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
pub struct Array32u8 {
    pub bits: [u8; 32]
}

impl Key for Array32u8 {
    fn from_u8(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut bits = [0u8; 32];
        bits.clone_from_slice(key);
        Array32u8 { bits }
    }
    fn as_slice<T, F: Fn(&[u8]) -> T> (&self, f: F) -> T {
        f(&self.bits)
    }
}