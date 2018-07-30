 #[cfg(test)]  
 mod test {
    // enigma_tools 
    use enigma_tools_u::attestation_service::service;
    use enigma_tools_u::attestation_service::constants;
    // this unit-test is for the attestation service 
    // it uses a hardcoded quote that is validated 
    // the test requests a report from the attestation service construct an object with the response 
    // for signing the report there's additional field that can be accessed via ASResponse.result.report_string
     #[test]
     fn test_get_response_attestation_service(){ 
        // build a request 
        let service : service::AttestationService = service::AttestationService::new(constants::ATTESTATION_SERVICE_URL);
        let quote = String::from("AgAAANoKAAAHAAYAAAAAABYB+Vw5ueowf+qruQGtw+54eaWW7MiyrIAooQw/uU3eBAT/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAALcVy53ugrfvYImaDi1ZW5RueQiEekyu/HmLIKYvg6OxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACGcCDM4cgbYe6zQSwWQINFsDvd21kXGeteDakovCXPDwjJ31WG0K+wyDDRo8PFi293DtIr6DgNqS/guQSkglPJqAIAALbvs91Ugh9/yhBpAyGQPth+UWXRboGkTaZ3DY8U+Upkb2NWbLPkXbcMbB7c3SAfV4ip/kPswyq0OuTTiJijsUyOBOV3hVLIWM4f2wVXwxiVRXrfeFs/CGla6rGdRQpFzi4wWtrdKisVK5+Cyrt2y38Ialm0NqY9FIjxlodD9D7TC8fv0Xog29V1HROlY+PvRNa+f2qp858w8j+9TshkvOAdE1oVzu0F8KylbXfsSXhH7d+n0c8fqSBoLLEjedoDBp3KSO0bof/uzX2lGQJkZhJ/RSPPvND/1gVj9q1lTM5ccbfVfkmwdN0B5iDA5fMJaRz5o8SVILr3uWoBiwx7qsUceyGX77tCn2gZxfiOICNrpy3vv384TO2ovkwvhq1Lg071eXAlxQVtPvRYOGgBAABydn7bEWdP2htRd46nBkGIAoNAnhMvbGNbGCKtNVQAU0N9f7CROLPOTrlw9gVlKK+G5vM1X95KTdcOjs8gKtTkgEos021zBs9R+whyUcs9npo1SJ8GzowVwTwWfVz9adw2jL95zwJ/qz+y5x/IONw9iXspczf7W+bwyQpNaetO9xapF6aHg2/1w7st9yJOd0OfCZsowikJ4JRhAMcmwj4tiHovLyo2fpP3SiNGzDfzrpD+PdvBpyQgg4aPuxqGW8z+4SGn+vwadsLr+kIB4z7jcLQgkMSAplrnczr0GQZJuIPLxfk9mp8oi5dF3+jqvT1d4CWhRwocrs7Vm1tAKxiOBzkUElNaVEoFCPmUYE7uZhfMqOAUsylj3Db1zx1F1d5rPHgRhybpNpxThVWWnuT89I0XLO0WoQeuCSRT0Y9em1lsozSu2wrDKF933GL7YL0TEeKw3qFTPKsmUNlWMIow0jfWrfds/Lasz4pbGA7XXjhylwum8e/I");
        let as_response : service::ASResponse = service.get_report(&quote).unwrap();
        // THE report as a string ready for signing 
        //println!("report to be signed string => {}",as_response.result.report_string );
        // example on how to access some param inside ASResponse
        //println!("report isv enclave quote status  => {}",as_response.result.report.isvEnclaveQuoteStatus );
        assert_eq!(true, as_response.result.validate);
        assert_eq!("2.0",as_response.jsonrpc );
     }
 }