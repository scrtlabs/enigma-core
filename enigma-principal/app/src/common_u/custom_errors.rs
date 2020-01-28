use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Unable to open config file")]
    FileDoesntExist,
    #[error("Unable to convert file content to string")]
    NotAString,
    #[error("Cannot parse data")]
    Parsing,
}

#[derive(Error, Debug)]
pub enum ReportManagerErr {
    #[error("An error occurred while trying to get the registration signing address from inside the enclave")]
    GetRegisterAddrErr,
    #[error("An error occurred while trying to get the Ethereum address from inside the enclave")]
    GetEtherAddrErr,
    #[error("Error while trying to produce quote")]
    QuoteErr,
}