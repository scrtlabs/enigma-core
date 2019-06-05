//! # Errors
//! This is a module for the errors of this crate.
//! we use Failure to handle the Error and Display traits and other conversions.
//!
use failure::Fail;

/// This Error enum is used to represent errors from this library.
/// Pro tip: If you want to add a string message to the error and you always hard code it,
/// then you can use `&'static str` instead of String, this will make your code much nicer.
#[derive(Debug, Fail, Clone)]
pub enum ToolsError {
    /// The `MessagingError` error.
    ///
    /// This error means that there was a Messaging problem (e.g. couldn't deserialize a message)
    #[fail(display = "There's an error with the messaging: {}", err)]
    MessagingError {
        /// `Err` is the custom message that should explain what and where was the problem.
        err: &'static str
    },
}
