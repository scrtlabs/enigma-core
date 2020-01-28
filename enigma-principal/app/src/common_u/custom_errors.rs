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