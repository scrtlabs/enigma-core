use rlp;
use enigma_tools_u;
use enigma_tools_u::attestation_service::service;
use enigma_tools_u::attestation_service::constants;
use failure::Error;
// encoding in surface https://github.com/enigmampc/surface/blob/e179790347e03666ad24829545429bcb69867849/src/surface/communication/core/worker.py#L105

pub fn get_report()->Result<service::ASResponse, Error>{
    let service : service::AttestationService = service::AttestationService::new(constants::ATTESTATION_SERVICE_URL);
    let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
    let as_response : service::ASResponse = service.get_report(&quote).unwrap();
    Ok(as_response)
}

pub fn rlp_encode_registration_params(certificate : &String , signature : &String, report : &String)->Vec<u8>{
    let clear = vec![report.as_str(), certificate.as_str(), signature.as_str()];
    let encoded = rlp::encode_list::<&str,&str>(&clear).to_vec();
    encoded
}
pub fn run(){
    let as_response = get_report().unwrap();
    // certificate,signature,report_string are all need to be rlp encoded and send to register() func in enigma contract
    let certificate = as_response.result.certificate;
    let signature = as_response.result.signature;
    let report_string = as_response.result.report_string;
    // rlp encoding 
    let encoded : Vec<u8> = rlp_encode_registration_params(&certificate, &signature, &report_string);
    
    // let animal = "cat";
    // let out = rlp::encode(&animal).to_vec();
    // assert_eq!(out, vec![0x83, b'c', b'a', b't']);
    // println!("original = {} encoded = |{:?}|" ,animal, out);
}