use jsonrpc_minihttp_server::jsonrpc_core::*;
use jsonrpc_minihttp_server::cors::AccessControlAllowOrigin;
use std::string::ToString;
use failure::Error;
use jsonrpc_minihttp_server::ServerBuilder;
use jsonrpc_minihttp_server::DomainsValidation;

pub struct PrincipalHttpServer {
    pub port: String,
}

impl PrincipalHttpServer {
    pub fn new(port: &str) -> PrincipalHttpServer {
        PrincipalHttpServer { port: port.to_string() }
    }
    pub fn start(&self) {
        let mut io = IoHandler::default();
        io.add_method("say_hello", |_| {
            Ok(Value::String("hello".into()))
        });

        let server = ServerBuilder::new(io)
            .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Null]))
            .start_http(&"127.0.0.1:3030".parse().unwrap())
//            .expect("Unable to start RPC server");
            .unwrap();

        server.wait().unwrap();
    }
}
