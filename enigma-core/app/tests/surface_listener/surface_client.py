#!/usr/bin/python3
import zmq
import json

context = zmq.Context()
socket = context.socket(zmq.REQ)

socket.connect('tcp://127.0.0.1:5552')

# request worker evm computation 
evm_data = json.dumps({
                    "cmd" : "execevm",
                    "bytecode" :"the evm bytecode",
                    "callable" : "the evm callable",
                    "callable_args" :"the callable args",
                    "preprocessor": "rand() preprocessor",
                    "callback": "callback(stuff...)"
                  })
# request quote + pubkey for registration 
register_data = json.dumps({
                    "cmd" : "getregister",
                  })
# stops the server 
stop_data = json.dumps({
					"cmd" : "stop",
				})
#send 
socket.send_string(register_data)
#read
from_server = socket.recv_json()
print('got from server {}'.format(from_server))