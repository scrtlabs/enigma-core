//! # Errors
//! This module contains the `CryptoError` enum which is the used error type in this crate.
//!
use failure::Fail;
use crate::localstd::fmt;

/// This Error enum tries to give the exact explanation of the error *without* revealing any secrets.
/// I tried to minimize the usage of cfg conditions here and have unified errors for sgx and std as much as I could.
#[allow(missing_docs)]
#[derive(Fail)]
#[cfg_attr(feature = "sgx", derive(Clone))]
pub enum CryptoError {
    /// The `DerivingKeyError` error.
    ///
    /// This error means that the ECDH process failed.
    DerivingKeyError { self_key: [u8; 64], other_key: [u8; 64] },
    /// The `MissingKeyError` error.
    ///
    /// This error means that a key was missing.
    MissingKeyError { key_type: &'static str },
    /// The `DecryptionError` error.
    ///
    /// This error means that the symmetric decryption has failed for some reason.
    DecryptionError,
    /// The `ImproperEncryption` error.
    ///
    /// This error means that the ciphertext provided was imporper.
    /// e.g. MAC wasn't valid, missing IV etc.
    ImproperEncryption,
    /// The `EncryptionError` error.
    ///
    /// This error means that the symmetric encryption has failed for some reason.
    EncryptionError,
    /// The `SigningError` error.
    ///
    /// This error means that the signing process has failed for some reason.
    SigningError { hashed_msg: [u8; 32] },
    /// The `ParsingError` error.
    ///
    /// This error means that the signature couldn't be parsed correctly.
    ParsingError { sig:  [u8; 65] },
    /// The `RecoveryError` error.
    ///
    /// This error means that the public key can't be recovered from that message & signature.
    RecoveryError { sig: [u8; 65] },
    /// The `KeyError` error.
    ///
    /// This error means that a key wasn't vaild.
    /// e.g. PrivateKey, PubliKey, SharedSecret.
    #[cfg(feature = "asymmetric")]
    KeyError { key_type: &'static str, err: Option<secp256k1::Error> },
    #[cfg(not(feature = "asymmetric"))]
    KeyError { key_type: &'static str, err: Option<()> },
    /// The `RandomError` error.
    ///
    /// This error means that the random function had failed generating randomness.
    #[cfg(feature = "std")]
    RandomError { err: rand_std::Error },
    #[cfg(feature = "sgx")]
    RandomError { err: sgx_types::sgx_status_t },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CryptoError::*;
        match self {
            DerivingKeyError{ self_key, other_key} => write!(f, "Failed to derive a key with ECDH: self: {:?}, other: {:?}", &self_key[..], &other_key[..]),
            KeyError { key_type, err } => write!(f, "The {} Isn't valid, err: {:?}", key_type, err),
            MissingKeyError { key_type } => write!(f, "The following key is missing: {}", key_type),
            DecryptionError => write!(f, "Failed Decrypting"),
            ImproperEncryption => write!(f, "Improper Encryption"),
            EncryptionError => write!(f, "Failed Encrypting"),
            SigningError { hashed_msg } => write!(f, "Signing the message failed, msg hash: {:?}", hashed_msg),
            ParsingError { sig } => write!(f, "Parsing the signature failed, sig: {:?}", &sig[..]),
            RecoveryError { sig } => write!(f, "Recovering the pubkey failed using the sig: {:?}", &sig[..]),
            #[cfg(any(feature = "std", feature = "sgx"))]
            RandomError{ err } => write!(f, "Failed Generating a random. Error: {:?}", err),
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
