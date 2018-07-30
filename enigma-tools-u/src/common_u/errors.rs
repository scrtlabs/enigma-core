
// error while request attestation service 
#[derive(Fail, Debug)]
#[fail(display = "Error while using the attestation service info = ({})", message)]
pub struct AttestationServiceErr{
    pub message : String,
}

#[derive(Fail, Debug)]
#[fail(display = "Error while decoding the quote = ({})", message)]
pub struct QuoteErr{
    pub message : String,
}
