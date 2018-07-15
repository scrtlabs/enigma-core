use serde::*;
use serde_derive::*;
use serde_json;
use serde_json::{Value};
use reqwest;
use reqwest::StatusCode;
use failure::Error;
use common_u::errors;
use attestation_service;
use base64;
use std::io::Read;
use std::mem;

#[derive(Serialize, Deserialize, Debug)]
pub struct ASReport {
    pub id : String, 
    pub timestamp : String,
    pub isvEnclaveQuoteStatus : String,
    pub platformInfoBlob : String,
    pub isvEnclaveQuoteBody : String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResult {
    pub ca : String, 
    pub certificate : String,
    pub report : ASReport,
    pub report_string : String,
    pub signature : String, 
    pub validate : bool
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResponse {
    pub id : i64,
    pub jsonrpc : String, 
    pub result : ASResult
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub quote : String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteRequest {
    pub jsonrpc : String, 
    pub method : String, 
    pub params : Params, 
    pub id : i32, 
}

#[derive(Default)]
pub struct Quote {
    pub body: QBody,
    pub report_body: QReportBody,
}

pub struct QBody { // size: 48
    pub version: [u8; 2],
    pub signature_type: [u8; 2],
    pub gid: [u8; 4],
    pub isv_svn_qe: [u8; 2],
    pub isv_svn_pce: [u8; 2],
    pub reserved: [u8; 4],
    pub base_name: [u8; 32],
}

pub struct QReportBody { // size: 384
    pub cpu_svn: [u8; 16],
    pub misc_select: [u8; 4],
    pub reserved: [u8; 28],
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    pub reserved3: [u8; 96],
    pub isv_prod_id: [u8; 2],
    pub isv_svn: [u8; 2],
    pub reserved4: [u8; 60],
    pub report_data: [u8; 64],
}

pub struct AttestationService {
    connection_str : String,
}
impl AttestationService{
    pub fn new(conn_str: &str)->AttestationService{
        AttestationService{
            connection_str : conn_str.to_string()
        }
    }
    pub fn get_report(&self,quote : &String)-> Result<ASResponse,Error>{
        let request : QuoteRequest = self.build_request(quote);
        let response : ASResponse =  self.send_request(request)?;
        Ok(response)
    }
    // input: encrypted enclave quote 
    // output : JSON-RPC request object
    pub fn build_request(&self, quote : &String) -> QuoteRequest{
        QuoteRequest{
            jsonrpc : "2.0".to_string(),
            method : "validate".to_string(),
            params : Params{
                quote : quote.to_string(),
            },
            id : 1
        }
    }
    // request the report object 
    pub fn send_request(&self,quote_req : QuoteRequest)-> Result<ASResponse,Error>{
        
        let client = reqwest::Client::new();
        let mut res = client.post(self.connection_str.as_str())
            .json(&quote_req)
            .send().unwrap();
        let response_str =  res.text().unwrap();
        let json_response : Value = serde_json::from_str(response_str.as_str()).unwrap();

        if res.status().is_success(){
            // parse the Json object into an ASResponse struct 
            let response : ASResponse = self.unwrap_response(&json_response);
            Ok(response)

        }else if res.status().is_server_error(){

             let mut message = String::from("[-] AttestationService: Server Error happened. Status code: ");
             message.push_str(res.status().to_string().as_str());
             Err(errors::AttestationServiceErr{
                 message : message
             }.into())

        }else{

             let mut message = String::from("[-] AttestationService: Unkown Error happened. Status code: ");
             message.push_str(res.status().to_string().as_str());
             Err(errors::AttestationServiceErr{
                 message : message
             }.into())

        }
    }
    // parse the response json into an ASResponse
    fn unwrap_report_obj(&self,r : &Value) -> ASReport {
        let report_str = r["result"]["report"].as_str().unwrap();
        let report_obj : ASReport = serde_json::from_str(report_str).unwrap();
        report_obj
    }

    fn unwrap_result(&self,r : & Value) -> ASResult{
        let ca = r["result"]["ca"].as_str().unwrap();
        let certificate = r["result"]["certificate"].as_str().unwrap();
        let signature = r["result"]["signature"].as_str().unwrap();
        let validate = match r["result"]["validate"].as_str() {
            Some(v)=>{
                if v == "True"{
                    true
                }else{
                    false
                }
            },
            None =>{
                false
            },
        };
        let report : ASReport =  self.unwrap_report_obj(r);
        let result_obj : ASResult  = ASResult{
            ca: ca.to_string(), 
            certificate : certificate.to_string(), 
            signature : signature.to_string(), 
            validate : validate , 
            report : report , 
            report_string :  r["result"]["report"].as_str().unwrap().to_string()
        };
        result_obj
    }

    fn unwrap_response(&self,r : & Value) -> ASResponse{
        let result : ASResult = self.unwrap_result(r);
        let id = r["id"].as_i64().unwrap();
        let jsonrpc = r["jsonrpc"].as_str().unwrap();
        let response_obj : ASResponse = ASResponse {
            id : id , 
            jsonrpc : jsonrpc.to_string(),
            result : result
        };
        response_obj
    }

}

impl ASResponse {
    pub fn get_quote(&self) -> Result<Quote, Error> {
        Quote::from_base64(&self.result.report.isvEnclaveQuoteBody)
    }
}


impl Quote {
    pub fn from_base64(encoded_quote: &str) -> Result<Quote, Error> {
        let quote_bytes =  base64::decode(encoded_quote)?;
        let mut result: Quote = Default::default();
//        let mut sig_len = [0u8; 4]; sig_len.copy_from_slice(&quote_bytes[432..436]);
        Ok(Quote {
            body: QBody::from_bytes_read(&mut &quote_bytes[..48])?,
            report_body: QReportBody::from_bytes_read(&mut &quote_bytes[48..432])?,
        })
    }
}

//impl Default for Quote {
//    fn default() -> Quote {
//        unsafe { mem::zeroed() }
//    }
//}

impl QBody {
    pub fn from_bytes_read<R: Read> (body: &mut R) -> Result<QBody, Error> {
        let mut result: QBody = Default::default();

        body.read_exact(&mut result.version)?;
        body.read_exact(&mut result.signature_type)?;
        body.read_exact(&mut result.gid)?;
        body.read_exact(&mut result.isv_svn_qe)?;
        body.read_exact(&mut result.isv_svn_pce)?;
        body.read_exact(&mut result.reserved)?;
        body.read_exact(&mut result.base_name)?;

        if body.read(&mut [0u8])? != 0 {
            unimplemented!();
        }
        Ok(result)
    }
}

impl Default for QBody {
    fn default() -> QBody {
        unsafe { mem::zeroed() }
    }
}

impl QReportBody { // Size: 384
    pub fn from_bytes_read<R: Read> (body: &mut R) -> Result<QReportBody, Error> {
        let mut result: QReportBody = Default::default();

        body.read_exact(&mut result.cpu_svn)?;
        body.read_exact(&mut result.misc_select)?;
        body.read_exact(&mut result.reserved)?;
        body.read_exact(&mut result.attributes)?;
        body.read_exact(&mut result.mr_enclave)?;
        body.read_exact(&mut result.reserved2)?;
        body.read_exact(&mut result.mr_signer)?;
        body.read_exact(&mut result.reserved3)?;
        body.read_exact(&mut result.isv_prod_id)?;
        body.read_exact(&mut result.isv_svn)?;
        body.read_exact(&mut result.reserved4)?;
        body.read_exact(&mut result.report_data)?;

        if body.read(&mut [0u8])? != 0 {
            unimplemented!();
        }
        Ok(result)
    }
}

impl Default for QReportBody {
    fn default() -> QReportBody {
        unsafe { mem::zeroed() }
    }
}


 #[cfg(test)]  
 mod test {
     use attestation_service::service::*;
     use attestation_service;
     use std::str::from_utf8;
    // this unit-test is for the attestation service
    // it uses a hardcoded quote that is validated 
    // the test requests a report from the attestation service construct an object with the response 
    // for signing the report there's additional field that can be accessed via ASResponse.result.report_string
     #[test]
     fn test_get_response_attestation_service(){ 
        // build a request 
        let service : AttestationService = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
        let as_response : ASResponse = service.get_report(&quote).unwrap();
        // THE report as a string ready for signing 
        //println!("report to be signed string => {}",as_response.result.report_string );
        // example on how to access some param inside ASResponse
        //println!("report isv enclave quote status  => {}",as_response.result.report.isvEnclaveQuoteStatus );
        assert_eq!(true, as_response.result.validate);
        assert_eq!("2.0",as_response.jsonrpc );
     }
 }