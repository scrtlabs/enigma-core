/// This module is a pretty hacky wrokaround for not being able to self-sign transactions using `rust-web3`.
/// There is a PR adding the core functionality inside `rust-web3` here:
/// https://github.com/tomusdrw/rust-web3/pull/279
/// On top of that, you can implement the `signed_call_with_confirmations` method on
/// [![web3::contract::Contract]][web3-contract] directly, without all the hacks you can find in the branch introducing
/// this file. (Please refer to the first commit introducing this file if you are viewing this in the distant future)
///
/// If you are seeing this on top of `develop` or even `master` after the above linked PR to `rust-web3` has
/// been merged, please open a task to revert the whole branch introducing this file, and then use the functionality
/// they eventually introduce instead of this monstrosity.
///
/// Thank You and Good Luck!
///
/// [web3-contract]: https://tomusdrw.github.io/rust-web3/web3/contract/struct.Contract.html

use failure;

use ethabi;
use ethereum_types;
use ethereum_tx_sign;
use web3::{
    self,
    Transport,
    api::Namespace,
    confirm::{
        self,
    },
    contract::{
        Options,
        tokens::Tokenize,
    },
    futures::Future,
    types::{
        Address,
        Bytes,
        U256,
        H256,
        BlockNumber,
    },
};

/// I implement this struct to coalesce all the errors from the crates used in this file into one struct, that can
/// be `?`-cast into `failure::Fail`
#[derive(Debug, failure::Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Web3Error(String),

    #[fail(display = "{}", _0)]
    Web3ContractError(String),

    #[fail(display = "{}", _0)]
    EthabiError(String),

    #[fail(display = "{}", _0)]
    IoError(#[cause] std::io::Error),

    #[fail(display = "{}", _0)]
    SerdeJsonError(#[cause] serde_json::Error),

    #[fail(display = "{}", _0)]
    ParseIntError(#[cause] std::num::ParseIntError),
}

macro_rules! from_error_to_string {
    ($variant: path, $source: ty) => {
        impl From<$source> for Error {
            fn from(other: $source) -> Self {
                $variant(other.to_string())
            }
        }
    }
}

from_error_to_string!(Error::Web3Error, web3::Error);
from_error_to_string!(Error::Web3ContractError, web3::contract::Error);
from_error_to_string!(Error::EthabiError, ethabi::Error);

macro_rules! from_error {
    ($variant: path, $source: ty) => {
        impl From<$source> for Error {
            fn from(other: $source) -> Self {
                $variant(other)
            }
        }
    }
}

from_error!(Error::IoError, std::io::Error);
from_error!(Error::SerdeJsonError, serde_json::Error);
from_error!(Error::ParseIntError, std::num::ParseIntError);

fn option_to_u256(value: Option<U256>) -> ethereum_types::U256 {
    value.unwrap_or_else(|| ethereum_types::U256::from(0))
}

/// Confused? You should be. Please read the documentation in the top of this file.
pub fn signed_call_with_confirmations<T: Transport, P>(
    // general tools
    web3: &web3::api::Web3<T>,
    // contract details
    contract_abi: &ethabi::Contract,
    contract_address: Address,
    // sender details
    private_key: H256,
    from: Address, // Should belong to the private key
    // function details
    func: &str,
    params: P,
    // network details
    options: Options,
    chain_id: u8,
    confirmations: usize,
) -> Result<confirm::SendTransactionWithConfirmation<T>, Error>
    where
        P: Tokenize,
{
    let poll_interval = std::time::Duration::from_secs(1);

    let function = contract_abi.function(func)?;
    let fn_data = function.encode_input(&params.into_tokens())?;

    let nonce = if let Some(nonce) = options.nonce {
        nonce
    } else {
        web3.eth().transaction_count(from, Some(BlockNumber::Latest)).wait()?
    };

    let tx = ethereum_tx_sign::RawTransaction {
        nonce: nonce,
        to: Some(contract_address),
        value: option_to_u256(options.value),
        gas_price: option_to_u256(options.gas_price),
        gas: option_to_u256(options.gas),
        data: fn_data,
    };

    let signed_tx = tx.sign(&private_key, &chain_id);

    Ok(confirm::send_raw_transaction_with_confirmation(
        web3.eth().transport().clone(),
        Bytes::from(signed_tx),
        poll_interval,
        confirmations,
    ))
}
