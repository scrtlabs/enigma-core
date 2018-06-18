use zmq;
use serde_json;
use serde_json::{Value, Error};
use std::thread;
use std::time::Duration;
use evm_u::evm;
use esgx::equote;
use networking::constants;
use sgx_types::*;
use sgx_urts::SgxEnclave;


pub struct ClientHandler{}

impl ClientHandler {
    // public function to handle the surface requests 
    pub fn handle(&self, enclave : &SgxEnclave,responder : &zmq::Socket,msg :& str) -> Result<(bool), Error> {
        
        let mut keep_running : bool = true;

        let v: Value = serde_json::from_str(msg)?;

        let cmd : constants::Command = v["cmd"].as_str().unwrap().into();
        let result = match cmd {
            constants::Command::Execevm =>{
                let result = self.handle_execevm(responder, v.clone()).unwrap();
                println!("EVM Output result : {}",result );
                result
            },
            constants::Command::GetRegister =>{
                let result = self.handle_get_register(enclave, responder,  v.clone()).unwrap();
                println!("Enclave quote : {}", result);
                result
            },
            constants::Command::Stop=>{
                  keep_running = false;
                  let result = self.handle_stop().unwrap();
                  result
            },
            constants::Command::Unknown =>{
                println!("[Server] unkown command ");    
                String::from("")
            },
        };
        thread::sleep(Duration::from_millis(1000));
        responder.send_str(&result, 0).unwrap();
        Ok((keep_running))  
    }
    fn handle_stop(&self)->  Result<(String), Error>{   
        // serialize the response
        let str_result = serde_json::to_string(&constants::StopServer{
            errored : false,
            reason : String::from("stop request."),
        }).unwrap();
        // send 
        Ok(str_result)
    }
    // private function : handle execevm cmd 
    fn handle_execevm(&self,responder : &zmq::Socket, msg : Value)-> Result<(String), Error>{
            // get the EVM inputs 
            let evm_input = self.unwrap_execevm(msg);
            // make an ecall to encrypt+compute 
            let result : evm::ToServerEvm = evm::exec_evm(evm_input).unwrap();
            // serialize the result 
            let str_result = serde_json::to_string(&result).unwrap();
            // send 
        Ok((str_result))
    }
    // private function : handle getregister
    fn handle_get_register(&self,enclave: &SgxEnclave,responder : &zmq::Socket,msg : Value)->  Result<(String), Error>{   
        // ecall a quote + key 
        let encoded_quote = equote::produce_quote(enclave, &constants::SPID.to_owned());
        // ecall get the clear text public signing key 
        let pub_signing_key = equote::get_register_signing_key(enclave).unwrap();
        // serialize the result 
        let str_result = serde_json::to_string(&equote::GetRegisterResult{
            quote:encoded_quote, 
            pub_key: pub_signing_key })
            .unwrap();
        // send 
        Ok(str_result)
    }
    // private function : turn all JSON values to strings
    fn unwrap_execevm(&self, msg : Value) -> evm::FromServerEvm {
        evm::FromServerEvm::new(
        msg["bytecode"].as_str().unwrap().to_string(),
        msg["callable"].as_str().unwrap().to_string(), 
        msg["callableArgs"].as_str().unwrap().to_string(), 
        msg["preprocessor"].as_str().unwrap().to_string(), 
        msg["callback"].as_str().unwrap().to_string())
    }
}

pub struct Server<'a>{
    context : zmq::Context,
    responder : zmq::Socket,
    handler : ClientHandler,
    enclave: &'a SgxEnclave ,
}

impl<'a> Server<'a>{
    
    pub fn new(conn_str: &str, enclave: &'a SgxEnclave) -> Server<'a> {
        let ctx = zmq::Context::new();
        // Maybe this doesn't need to be mut?
        let mut rep = ctx.socket(zmq::REP).unwrap();
        rep.bind(conn_str).unwrap();
        let client_handler = ClientHandler{};
        Server {
            context: ctx,
            responder: rep,
            handler: client_handler,
            enclave : enclave,
        }
    }

    pub fn run(& mut self){
        let mut msg = zmq::Message::new().unwrap();
        loop {
            println!("[+] Server awaiting connection..." );
            self.responder.recv(&mut msg, 0).unwrap();
            match self.handler.handle(&self.enclave,&self.responder,&msg.as_str().expect("[-] Err in ClientHandler.handle()")){
                Ok(keep_running) =>{
                    if !keep_running{
                        println!("[+] Server shutting down... ");    
                        break;
                    }
                },
                Err(e)=>{
                    println!("[-] Server Err : {:?}",e);
                }
            }
        }
    }
}



// unit tests 

 #[cfg(test)]  
 mod test {
    use esgx::general::init_enclave;
    use networking::surface_server;
    use networking::constants;
    use std::thread;

    // can be tested with a client /app/tests/surface_listener/surface_client.pu
    // network message defitnitions can be found in /app/tests/surface_listener/message_type.definition
     #[test]
     #[ignore]
     fn test_run_server(){ 
            // initiate the enclave 
            let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                assert_eq!(0,1);
                return;
            },
        };
        // run the server 
        {
            let mut server = surface_server::Server::new(constants::CONNECTION_STR, &enclave);
            server.run();
        }
        
        // destroy the enclave 
        enclave.destroy();
     }
 }