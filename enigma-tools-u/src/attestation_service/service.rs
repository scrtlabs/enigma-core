//! # Attestation service.
//! all of the data here is directly from the API https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf
//! Some of this code is pretty old and can be rewritten in a more idiomatic way(and even generally better).

use base64;
use common_u::errors;
use failure::Error;
use hex::FromHex;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::{X509VerifyResult, X509};
use reqwest::{self, Client};
use rlp;
use serde_json;
use serde_json::Value;
use std::io::Read;
use std::mem;
use std::string::ToString;

const ATTESTATION_SERVICE_DEFAULT_RETRIES: u32 = 10;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ASReport {
    pub id: String,
    pub timestamp: String,
    pub version: usize,
    #[serde(rename = "isvEnclaveQuoteStatus")]
    pub isv_enclave_quote_status: String,
    #[serde(rename = "isvEnclaveQuoteBody")]
    pub isv_enclave_quote_body: String,
    #[serde(rename = "revocationReason")]
    pub revocation_reason: Option<String>,
    #[serde(rename = "pseManifestStatus")]
    pub pse_manifest_satus: Option<String>,
    #[serde(rename = "pseManifestHash")]
    pub pse_manifest_hash: Option<String>,
    #[serde(rename = "platformInfoBlob")]
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    #[serde(rename = "epidPseudonym")]
    pub epid_pseudonym: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResult {
    pub ca: String,
    pub certificate: String,
    pub report: ASReport,
    pub report_string: String,
    pub signature: String,
    pub validate: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResponse {
    pub id: i64,
    pub jsonrpc: String,
    pub result: ASResult,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub quote: String,
    pub production: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Params,
    pub id: i32,
}

#[derive(Default)]
pub struct Quote {
    pub body: QBody,
    pub report_body: QReportBody,
}

pub struct QBody {
    // size: 48
    pub version: [u8; 2],
    pub signature_type: [u8; 2],
    pub gid: [u8; 4],
    pub isv_svn_qe: [u8; 2],
    pub isv_svn_pce: [u8; 2],
    pub reserved: [u8; 4],
    pub base_name: [u8; 32],
}

pub struct QReportBody {
    // size: 384
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
    connection_str: String,
    /// amount of attempts per network call
    retries: u32,
}

impl AttestationService {
    pub fn new(conn_str: &str) -> AttestationService {
        AttestationService { connection_str: conn_str.to_string(), retries: ATTESTATION_SERVICE_DEFAULT_RETRIES }
    }

    pub fn new_with_retries(conn_str: &str, retries: u32) -> AttestationService {
        AttestationService { connection_str: conn_str.to_string(), retries }
    }

    #[logfn(TRACE)]
    pub fn get_report(&self, quote: String) -> Result<ASResponse, Error> {
        let request: QuoteRequest = self.build_request(quote);
        let response: ASResponse = self.send_request(&request)?;
        Ok(response)
    }

    // input: encrypted enclave quote
    // output : JSON-RPC request object
    pub fn build_request(&self, quote: String) -> QuoteRequest {
        QuoteRequest {
            jsonrpc: "2.0".to_string(),
            method: "validate".to_string(),
            params: Params {
                quote,
                production: true,
            },
            id: 1,
        }
    }

    fn attempt_request(&self, client: &Client, quote_req: &QuoteRequest) -> Result<ASResponse, Error> {
        let mut res = client.post(self.connection_str.as_str()).json(&quote_req).send()?;
        let response_str = res.text()?;
        let json_response: Value = serde_json::from_str(response_str.as_str())?;

        if res.status().is_success() && !json_response["error"].is_object() {
            // parse the Json object into an ASResponse struct
            let response: ASResponse = self.unwrap_response(&json_response);
            Ok(response)
        }
        else {
            let message = format!("[-] AttestationService: An Error occurred. \
                                            Status code: {:?}\nError response: {:?}",
                                            res.status(), json_response["error"]["message"].as_str());
            Err(errors::AttestationServiceErr { message }.into())
        }
    }
    // request the report object
    pub fn send_request(&self, quote_req: &QuoteRequest) -> Result<ASResponse, Error> {
        let client = reqwest::Client::new();
        self.attempt_request(&client, quote_req).or_else(|mut res_err| {
            for _ in 0..self.retries {
                match self.attempt_request(&client, quote_req) {
                    Ok(response) => return Ok(response),
                    Err(e) => res_err = e,
                }
            }
            return Err(res_err)
        })
    }

    // encode to rlp the report -> registration for the enigma contract
    pub fn rlp_encode_registration_params(&self, quote: String) -> Result<(Vec<u8>, ASResponse), Error> {
        let as_response = self.get_report(quote)?;
        // certificate,signature,report_string are all need to be rlp encoded and send to register() func in enigma contract
        let encoded;
        {
            let certificate = as_response.result.certificate.as_str();
            let signature = as_response.result.signature.as_str();
            let report_string = as_response.result.report_string.as_str();
            // rlp encoding
            let clear = vec![report_string, certificate, signature];
            encoded = rlp::encode_list::<&str, &str>(&clear).to_vec();
        }

        Ok((encoded, as_response))
    }

    // parse the response json into an ASResponse
    fn unwrap_report_obj(&self, r: &Value) -> ASReport {
        let report_str = r["result"]["report"].as_str().unwrap();
        let report_obj: ASReport = serde_json::from_str(report_str).unwrap();
        report_obj
    }

    #[logfn(TRACE)]
    fn unwrap_result(&self, r: &Value) -> ASResult {
        let ca = r["result"]["ca"].as_str().unwrap().to_string();
        let certificate = r["result"]["certificate"].as_str().unwrap().to_string();
        let signature = r["result"]["signature"].as_str().unwrap().to_string();
        let report_string = r["result"]["report"].as_str().unwrap().to_string();
        let validate = match r["result"]["validate"].as_str() {
            Some(v) => v == "True",
            None => false,
        };
        let report: ASReport = self.unwrap_report_obj(r);
        ASResult { ca, certificate, signature, validate, report, report_string }
    }

    fn unwrap_response(&self, r: &Value) -> ASResponse {
        let result: ASResult = self.unwrap_result(r);
        let id = r["id"].as_i64().unwrap();
        let jsonrpc = r["jsonrpc"].as_str().unwrap().to_string();

        ASResponse { id, jsonrpc, result }
    }
}

impl ASResponse {
    pub fn get_quote(&self) -> Result<Quote, Error> { Quote::from_base64(&self.result.report.isv_enclave_quote_body) }
}

impl ASResult {
    /// This function verifies the report and the chain of trust.
    #[logfn(TRACE)]
    pub fn verify_report(&self) -> Result<bool, Error> {
        let ca = X509::from_pem(&self.ca.as_bytes())?;
        let cert = X509::from_pem(&self.certificate.as_bytes())?;
        match ca.issued(&cert) {
            X509VerifyResult::OK => (),
            _ => return Ok(false),
        };
        let pubkey = cert.public_key()?;
        let sig: Vec<u8> = self.signature.from_hex()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)?;
        verifier.update(&self.report_string.as_bytes())?;
        Ok(verifier.verify(&sig)?)
    }
}

impl Quote {
    pub fn from_base64(encoded_quote: &str) -> Result<Quote, Error> {
        let quote_bytes = base64::decode(encoded_quote)?;

        Ok(Quote {
            body: QBody::from_bytes_read(&mut &quote_bytes[..48])?,
            report_body: QReportBody::from_bytes_read(&mut &quote_bytes[48..432])?,
        })
    }
}

impl QBody {

    /// This will read the data given to it and parse it byte by byte just like the API says
    /// The exact sizes of the field in `QBody` are extremley important.
    /// also the order in which `read_exact` is executed (filed by field just like the API) is also important
    /// because it reads the bytes sequentially.
    /// if the Reader is shorter or longer then the size of QBody it will return an error.
    pub fn from_bytes_read<R: Read>(body: &mut R) -> Result<QBody, Error> {
        let mut result: QBody = Default::default();

        body.read_exact(&mut result.version)?;
        body.read_exact(&mut result.signature_type)?;
        body.read_exact(&mut result.gid)?;
        body.read_exact(&mut result.isv_svn_qe)?;
        body.read_exact(&mut result.isv_svn_pce)?;
        body.read_exact(&mut result.reserved)?;
        body.read_exact(&mut result.base_name)?;

        if body.read(&mut [0u8])? != 0 {
            return Err(errors::QuoteErr { message: "String passed to QBody is too big".to_string() }.into());
        }
        Ok(result)
    }
}

impl Default for QBody {
    // Using `mem::zeroed()` here should be safe because all the fields are [u8]
    // *But* this isn't good practice. because if you add a Box/Vec or any other complex type this *will* become UB(Undefined Behavior).
    fn default() -> QBody { unsafe { mem::zeroed() } }
}

impl QReportBody {
    /// This will read the data given to it and parse it byte by byte just like the API says
    /// The exact sizes of the field in `QBody` are extremley important.
    /// also the order in which `read_exact` is executed (filed by field just like the API) is also important
    /// because it reads the bytes sequentially.
    /// if the Reader is shorter or longer then the size of QBody it will return an error.
    /// Overall Size: 384
    pub fn from_bytes_read<R: Read>(body: &mut R) -> Result<QReportBody, Error> {
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
            return Err(errors::QuoteErr { message: "String passed to QReportBody is too big".to_string() }.into());
        }
        Ok(result)
    }
}

impl Default for QReportBody {
    // Using `mem::zeroed()` here should be safe because all the fields are [u8]
    // *But* this isn't good practice. because if you add a Box/Vec or any other complex type this *will* become UB(Undefined Behavior).
    fn default() -> QReportBody { unsafe { mem::zeroed() } }
}

#[cfg(test)]
mod test {
    use crate::attestation_service::{self, service::*};
    use std::str::from_utf8;
    use hex::FromHex;
    use common_u::errors::AttestationServiceErr;

    // this unit-test is for the attestation service
    // it uses a hardcoded quote that is validated
    // the test requests a report from the attestation service construct an object with the response
    // for signing the report there's additional field that can be accessed via ASResponse.result.report_string
    #[test]
    fn test_get_response_attestation_service() {
        // build a request
        let service: AttestationService = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let quote = String::from("AgAAANoKAAAHAAYAAAAAALAzX9O8HMqPgE65imQgWS3bL6zst0H4QfxKAKurXXnVBAX/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIzp3AzhlP03bwcSpF+o5J3dlTq2zu0T03uf7PbnLtMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9sUtS1/Vn5lvk3Mxh+eX0AOjdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAADM2OO98uEjJQLRmzAvAqO4nirzimAHK0PjdgI8MT0xKDy/Paohf208N04YWgzl4kOjrG0X/T8LUphwzn3qB7XkycWqDO9RsLbNIpKRiVBIttztbn0/kxcwo6p54OeOLfhFbxaTn0wkzEYJhGWVR+j6IUGxubDwinf0fO+2vPu20kW1NzSV/Le8fyYzC4v5sIblVW8VZESsbuFd+bFbbcNzco9cH6cNI68FMkeMHoZF/Z4HvP7DR2sIiLnmYcavDbTlzG7OwaTDNcTCNfKsKReK76TRtu+m018QArsRTdrAwx7gZY2788RBpn0veSkU+v9QxNnZmqfpMolAXdu3ksQul4R8bzQ8HoiRkQvedCY8K+5j3GLvDjLCUgB4JP8Vhtt6KjABRO5o4+s3Uj2gBAABJIOqpxIvbG5zmizV7zUe4jAJQoPVM3jtcxXwU9PH5saXiCPHBpTEBpK/2r/5bUnIIBkshRbQ8/kP6/lLhEOu3Fkfh7UMMoizPO8uGQimLBGwbAFyAgU4G8TGeUbYWEGuRRJoKDoclzm9edJZ7mApMlmiT9t2VMLMsg7l49sO1T1TtgK/zpwwLvr2f4a/vmkJWviOcIRimFD+V20xw+EMXYl8Aj4x4Rw62+oiQe0mKvh3K4gXIamejnQHZ/Mrbeh8ai0n1J+GMeKFxxSkeytGZVrT+a75WjLAcJtt5QAU3Em1ELsWLUVUI58mLTe/u+hsjTlWizXAruElzhCIijvR96aHc+lzd/a+EmsQ4mI/mWPxqdoUciznhG4VlxNAhXSw8zn77k8m+1GaBSxvAUDwFOf/V3KcQUYp5Cswo1MD4t26Rn5LBqF1I0I27d/BHD+KUwl7W5doG4Ec6egnoofkSTUnjI3G+9btxIVV2nYWzfXauZzseiZQn");
        let as_response = service.get_report(quote).unwrap();
        // THE report as a string ready for signing
        //println!("report to be signed string => {}",as_response.result.report_string );
        // example on how to access some param inside ASResponse
        //println!("report isv enclave quote status  => {}",as_response.result.report.isvEnclaveQuoteStatus );
        assert_eq!(true, as_response.result.validate);
        assert_eq!("2.0", as_response.jsonrpc);
    }

    // Run the same test but with no option of retries
    #[test]
    fn test_get_response_attestation_service_no_retries() {
        // build a request with an initialized amount of 0 retries
        let service: AttestationService = AttestationService::new_with_retries(attestation_service::constants::ATTESTATION_SERVICE_URL, 0);
        let quote = String::from("AgAAANoKAAAHAAYAAAAAALAzX9O8HMqPgE65imQgWS3bL6zst0H4QfxKAKurXXnVBAX/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIzp3AzhlP03bwcSpF+o5J3dlTq2zu0T03uf7PbnLtMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9sUtS1/Vn5lvk3Mxh+eX0AOjdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAADM2OO98uEjJQLRmzAvAqO4nirzimAHK0PjdgI8MT0xKDy/Paohf208N04YWgzl4kOjrG0X/T8LUphwzn3qB7XkycWqDO9RsLbNIpKRiVBIttztbn0/kxcwo6p54OeOLfhFbxaTn0wkzEYJhGWVR+j6IUGxubDwinf0fO+2vPu20kW1NzSV/Le8fyYzC4v5sIblVW8VZESsbuFd+bFbbcNzco9cH6cNI68FMkeMHoZF/Z4HvP7DR2sIiLnmYcavDbTlzG7OwaTDNcTCNfKsKReK76TRtu+m018QArsRTdrAwx7gZY2788RBpn0veSkU+v9QxNnZmqfpMolAXdu3ksQul4R8bzQ8HoiRkQvedCY8K+5j3GLvDjLCUgB4JP8Vhtt6KjABRO5o4+s3Uj2gBAABJIOqpxIvbG5zmizV7zUe4jAJQoPVM3jtcxXwU9PH5saXiCPHBpTEBpK/2r/5bUnIIBkshRbQ8/kP6/lLhEOu3Fkfh7UMMoizPO8uGQimLBGwbAFyAgU4G8TGeUbYWEGuRRJoKDoclzm9edJZ7mApMlmiT9t2VMLMsg7l49sO1T1TtgK/zpwwLvr2f4a/vmkJWviOcIRimFD+V20xw+EMXYl8Aj4x4Rw62+oiQe0mKvh3K4gXIamejnQHZ/Mrbeh8ai0n1J+GMeKFxxSkeytGZVrT+a75WjLAcJtt5QAU3Em1ELsWLUVUI58mLTe/u+hsjTlWizXAruElzhCIijvR96aHc+lzd/a+EmsQ4mI/mWPxqdoUciznhG4VlxNAhXSw8zn77k8m+1GaBSxvAUDwFOf/V3KcQUYp5Cswo1MD4t26Rn5LBqF1I0I27d/BHD+KUwl7W5doG4Ec6egnoofkSTUnjI3G+9btxIVV2nYWzfXauZzseiZQn");
        let as_response = service.get_report(quote).unwrap();

        assert_eq!(true, as_response.result.validate);
        assert_eq!("2.0", as_response.jsonrpc);
    }

    #[test]
    fn test_response_attestation_service_failure_no_retries() {
        // build a faulty request
        let service: AttestationService = AttestationService::new_with_retries(attestation_service::constants::ATTESTATION_SERVICE_URL, 0);
        let quote = String::from("Wrong quote");
        let as_response = service.get_report(quote.clone());
        // if it's able to do the downcast, we got the correct error
        assert!(as_response.unwrap_err().downcast::<AttestationServiceErr>().is_ok());
    }

    // get rlp_encoded Vec<u8> that contains the bytes array for worker registration in the enigma smart contract.
    #[test]
    fn test_get_response_attestation_service_rlp_encoded() {
        // build a request
        let service: AttestationService = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let quote = String::from("AgAAANoKAAAHAAYAAAAAALAzX9O8HMqPgE65imQgWS3bL6zst0H4QfxKAKurXXnVBAX/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIzp3AzhlP03bwcSpF+o5J3dlTq2zu0T03uf7PbnLtMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9sUtS1/Vn5lvk3Mxh+eX0AOjdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAADM2OO98uEjJQLRmzAvAqO4nirzimAHK0PjdgI8MT0xKDy/Paohf208N04YWgzl4kOjrG0X/T8LUphwzn3qB7XkycWqDO9RsLbNIpKRiVBIttztbn0/kxcwo6p54OeOLfhFbxaTn0wkzEYJhGWVR+j6IUGxubDwinf0fO+2vPu20kW1NzSV/Le8fyYzC4v5sIblVW8VZESsbuFd+bFbbcNzco9cH6cNI68FMkeMHoZF/Z4HvP7DR2sIiLnmYcavDbTlzG7OwaTDNcTCNfKsKReK76TRtu+m018QArsRTdrAwx7gZY2788RBpn0veSkU+v9QxNnZmqfpMolAXdu3ksQul4R8bzQ8HoiRkQvedCY8K+5j3GLvDjLCUgB4JP8Vhtt6KjABRO5o4+s3Uj2gBAABJIOqpxIvbG5zmizV7zUe4jAJQoPVM3jtcxXwU9PH5saXiCPHBpTEBpK/2r/5bUnIIBkshRbQ8/kP6/lLhEOu3Fkfh7UMMoizPO8uGQimLBGwbAFyAgU4G8TGeUbYWEGuRRJoKDoclzm9edJZ7mApMlmiT9t2VMLMsg7l49sO1T1TtgK/zpwwLvr2f4a/vmkJWviOcIRimFD+V20xw+EMXYl8Aj4x4Rw62+oiQe0mKvh3K4gXIamejnQHZ/Mrbeh8ai0n1J+GMeKFxxSkeytGZVrT+a75WjLAcJtt5QAU3Em1ELsWLUVUI58mLTe/u+hsjTlWizXAruElzhCIijvR96aHc+lzd/a+EmsQ4mI/mWPxqdoUciznhG4VlxNAhXSw8zn77k8m+1GaBSxvAUDwFOf/V3KcQUYp5Cswo1MD4t26Rn5LBqF1I0I27d/BHD+KUwl7W5doG4Ec6egnoofkSTUnjI3G+9btxIVV2nYWzfXauZzseiZQn");
        let (rlp_encoded, as_response) = service.rlp_encode_registration_params(quote).unwrap();
        assert!(!rlp_encoded.is_empty());
        assert_eq!(true, as_response.result.validate);
        assert_eq!("2.0", as_response.jsonrpc);
    }
    #[test]
    fn test_decoding_quote() {
        let isv_enclave_quote = "AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+5gbJslhOX9eWDNazWpHhBVBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAABIhP23bLUNSZ1yvFIrZa0pu/zt6/n3X8qNjMVbWgOGDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAweDRlNmRkMjg0NzdkM2NkY2QzMTA3NTA3YjYxNzM3YWFhMTU5MTYwNzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let quote = Quote::from_base64(&isv_enclave_quote).unwrap();
        let data = quote.report_body.report_data;
        let data_str = from_utf8(&data).unwrap();
        assert_eq!(data_str.trim_end_matches("\x00"), "0x4e6dd28477d3cdcd3107507b61737aaa15916070");
    }

    #[test]
    fn test_verify_report() {
        let report = ASResult {
             ca: "-----BEGIN CERTIFICATE-----\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\nDaVzWh5aiEx+idkSGMnX\n-----END CERTIFICATE-----".to_string(),
             certificate: "-----BEGIN CERTIFICATE-----\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\n-----END CERTIFICATE-----".to_string(),
             report: Default::default(),
             report_string: "{\"id\":\"100342731086430570647295023189732744265\",\"timestamp\":\"2018-07-15T16:06:47.993263\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000100000505020401010000000000000000000007000006000000020000000000000ADAD85ADE5C84743B9E8ABF2638808A7597A6EEBCEAA6A041429083B3CF232D6F746C7B19C832166D8ABB60F90BCE917270555115B0050F7E65B81253F794F665AA\",\"isvEnclaveQuoteBody\":\"AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+5gbJslhOX9eWDNazWpHhBVBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAABIhP23bLUNSZ1yvFIrZa0pu/zt6/n3X8qNjMVbWgOGDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAweDRlNmRkMjg0NzdkM2NkY2QzMTA3NTA3YjYxNzM3YWFhMTU5MTYwNzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}".to_string(),
             signature: "9e6a05bf42a627e3066b0067dc98bc22670df0061e42eed6a5af51ffa2e3b41949b6b177980b68c43855d4df71b2817b30f54bc40566225e6b721eb21fc0aba9b58e043bfaaae320e8d9613d514c0694b36b3fe41588b15480a6f7a4d025c244af531c7145d37f8b28c223bfb46c157470246e3dbd4aa15681103df2c8fd47bb59f7b827de559992fd24260e1113912bd98ba5cd769504bb5f21471ecd4f7713f600ae5169761c9047c09d186ad91f5ff89893c13be15d11bb663099192bcf2ce81f3cbbc28c9db93ce1a4df1141372d0d738fd9d0924d1e4fe58a6e2d12a5d2f723e498b783a6355ca737c4b0feeae3285340171cbe96ade8d8b926b23a8c90".to_string(),
             validate: true,
         };
        assert!(report.verify_report().unwrap());
    }

    #[test]
    fn test_attestation_service_decode_and_verify() {
        let service: AttestationService = AttestationService::new(attestation_service::constants::ATTESTATION_SERVICE_URL);
        let encrypted_quote = String::from("AgAAANoKAAAHAAYAAAAAALAzX9O8HMqPgE65imQgWS3bL6zst0H4QfxKAKurXXnVBAX/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAIzp3AzhlP03bwcSpF+o5J3dlTq2zu0T03uf7PbnLtMYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9sUtS1/Vn5lvk3Mxh+eX0AOjdoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAADM2OO98uEjJQLRmzAvAqO4nirzimAHK0PjdgI8MT0xKDy/Paohf208N04YWgzl4kOjrG0X/T8LUphwzn3qB7XkycWqDO9RsLbNIpKRiVBIttztbn0/kxcwo6p54OeOLfhFbxaTn0wkzEYJhGWVR+j6IUGxubDwinf0fO+2vPu20kW1NzSV/Le8fyYzC4v5sIblVW8VZESsbuFd+bFbbcNzco9cH6cNI68FMkeMHoZF/Z4HvP7DR2sIiLnmYcavDbTlzG7OwaTDNcTCNfKsKReK76TRtu+m018QArsRTdrAwx7gZY2788RBpn0veSkU+v9QxNnZmqfpMolAXdu3ksQul4R8bzQ8HoiRkQvedCY8K+5j3GLvDjLCUgB4JP8Vhtt6KjABRO5o4+s3Uj2gBAABJIOqpxIvbG5zmizV7zUe4jAJQoPVM3jtcxXwU9PH5saXiCPHBpTEBpK/2r/5bUnIIBkshRbQ8/kP6/lLhEOu3Fkfh7UMMoizPO8uGQimLBGwbAFyAgU4G8TGeUbYWEGuRRJoKDoclzm9edJZ7mApMlmiT9t2VMLMsg7l49sO1T1TtgK/zpwwLvr2f4a/vmkJWviOcIRimFD+V20xw+EMXYl8Aj4x4Rw62+oiQe0mKvh3K4gXIamejnQHZ/Mrbeh8ai0n1J+GMeKFxxSkeytGZVrT+a75WjLAcJtt5QAU3Em1ELsWLUVUI58mLTe/u+hsjTlWizXAruElzhCIijvR96aHc+lzd/a+EmsQ4mI/mWPxqdoUciznhG4VlxNAhXSw8zn77k8m+1GaBSxvAUDwFOf/V3KcQUYp5Cswo1MD4t26Rn5LBqF1I0I27d/BHD+KUwl7W5doG4Ec6egnoofkSTUnjI3G+9btxIVV2nYWzfXauZzseiZQn");
        let response = service.get_report(encrypted_quote).unwrap();
        let quote = response.get_quote().unwrap();
        let address = "fdb14b52d7f567e65be4dccc61f9e5f400e8dda0".from_hex().unwrap();
        assert_eq!(&quote.report_body.report_data[..20], &address[..]);
        assert!(response.result.verify_report().unwrap());
    }
}
