use failure::Fail;
use arrayvec::ArrayVec;

#[derive(Debug, Fail)]
#[cfg_attr(feature = "sgx", derive(Clone))]
pub enum CryptoError {
    #[fail(display = "Failed to derive a key with ECDH: self: {:?}, other: {:?}", self_key, other_key)]
    DerivingKeyError { self_key: ArrayVec<[u8; 64]>, other_key: ArrayVec<[u8; 64]> },

    #[cfg(feature = "asymmetric")]
    #[fail(display = "The {} Isn't valid, err: {:?}", key_type, err)]
    KeyError { key_type: &'static str, err: Option<secp256k1::Error> },

    #[fail(display = "The following key is missing: {}", key_type)]
    MissingKeyError { key_type: &'static str },

    #[cfg(not(feature = "asymmetric"))]
    #[fail(display = "The {} Isn't valid, err: {:?}", key_type, err)]
    KeyError { key_type: &'static str, err: Option<()> },

    #[fail(display = "Failed Decrypting")]
    DecryptionError,

    #[fail(display = "Improper Encryption")]
    ImproperEncryption,

    #[fail(display = "Failed Encrypting")]
    EncryptionError,

    #[fail(display = "Signing the message failed, msg hash: {:?}", hashed_msg)]
    SigningError { hashed_msg: [u8; 32] },

    #[fail(display = "Parsing the signature failed, sig: {:?}\nrecovery: {:?}", sig, recovery)]
    ParsingError { sig:  ArrayVec<[u8; 64]>, recovery: u8 },

#[fail(display = "Recovering the pubkey failed using the sig: {:?} and recovery id: {:?}", sig, recovery)]
    RecoveryError { sig: ArrayVec<[u8; 64]>, recovery: u8},

    #[cfg(feature = "std")]
    #[fail(display = "Failed Generating a random. rand Error: {:?}", err)]
    RandomError { err: rand_std::Error },

    #[cfg(feature = "sgx")]
    #[fail(display = "Failed Generating a random.  SGX Error: {:?}", err)]
    RandomError { err: sgx_types::sgx_status_t },
}