use failure::Fail;
use crate::localstd::fmt;

#[derive(Fail)]
#[cfg_attr(feature = "sgx", derive(Clone))]
pub enum CryptoError {
    DerivingKeyError { self_key: [u8; 64], other_key: [u8; 64] },
    MissingKeyError { key_type: &'static str },
    DecryptionError,
    ImproperEncryption,
    EncryptionError,
    SigningError { hashed_msg: [u8; 32] },
    ParsingError { sig:  [u8; 65] },
    RecoveryError { sig: [u8; 65] },
    #[cfg(feature = "asymmetric")]
    KeyError { key_type: &'static str, err: Option<secp256k1::Error> },
    #[cfg(not(feature = "asymmetric"))]
    KeyError { key_type: &'static str, err: Option<()> },
    #[cfg(feature = "std")]
    RandomError { err: rand_std::Error },
    #[cfg(feature = "sgx")]
    RandomError { err: sgx_types::sgx_status_t },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CryptoError::*;
        match &self {
            &DerivingKeyError{ self_key, other_key} => write!(f, "Failed to derive a key with ECDH: self: {:?}, other: {:?}", &self_key[..], &other_key[..]),
            &KeyError { key_type, err } => write!(f, "The {} Isn't valid, err: {:?}", key_type, err),
            &MissingKeyError { key_type } => write!(f, "The following key is missing: {}", key_type),
            &DecryptionError => write!(f, "Failed Decrypting"),
            &ImproperEncryption => write!(f, "Improper Encryption"),
            &EncryptionError => write!(f, "Failed Encrypting"),
            &SigningError { hashed_msg } => write!(f, "Signing the message failed, msg hash: {:?}", hashed_msg),
            &ParsingError { sig } => write!(f, "Parsing the signature failed, sig: {:?}", &sig[..]),
            &RecoveryError { sig } => write!(f, "Recovering the pubkey failed using the sig: {:?}", &sig[..]),
            #[cfg(any(feature = "std", feature = "sgx"))]
            &RandomError{ err } => write!(f, "Failed Generating a random. Error: {:?}", err),
        }
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CryptoError::*;
        match &self {
            DerivingKeyError{ self_key, other_key} => {
                let mut debug_builder = f.debug_struct("DerivingKeyError");
                debug_builder.field("self_key", &&self_key[..]);
                debug_builder.field("other_key", &&other_key[..]);
                debug_builder.finish()
            }
            KeyError { key_type, err } => {
                let mut debug_builder = f.debug_struct("KeyError");
                debug_builder.field("key_type", key_type);
                debug_builder.field("err", err);
                debug_builder.finish()
            },
            MissingKeyError { ref key_type } => {
                let mut debug_builder = f.debug_struct("MissingKeyError");
                debug_builder.field("key_type", key_type);
                debug_builder.finish()
            },
            DecryptionError => {
                let mut debug_builder = f.debug_tuple("DecryptionError");
                debug_builder.finish()
            },
            ImproperEncryption => {
                let mut debug_builder = f.debug_tuple("ImproperEncryption");
                debug_builder.finish()
            },
            EncryptionError => {
                let mut debug_builder = f.debug_tuple("EncryptionError");
                debug_builder.finish()
            },
            SigningError { ref hashed_msg } => {
                let mut debug_builder = f.debug_struct("DerivingKeyError");
                debug_builder.field("hashed_msg", hashed_msg);
                debug_builder.finish()
            },
            ParsingError { ref sig } => {
                let mut debug_builder = f.debug_struct("ParsingError");
                debug_builder.field("sig", &&sig[..]);
                debug_builder.finish()
            },
            RecoveryError { ref sig } => {
                let mut debug_builder = f.debug_struct("RecoveryError");
                debug_builder.field("self_key", &&sig[..]);
                debug_builder.finish()
            },
            #[cfg(any(feature = "std", feature = "sgx"))]
            RandomError{ ref err } => {
                let mut debug_builder = f.debug_struct("RandomError");
                debug_builder.field("err", err);
                debug_builder.finish()
            },
        }
    }
}
