use failure::Fail;

#[derive(Debug, Fail, Clone)]
pub enum ToolsError {
    #[fail(display = "There's an error with the messaging: {}", err)]
    MessagingError { err: &'static str },
}
