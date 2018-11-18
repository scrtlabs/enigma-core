#![allow(unknown_lints)]

use ethabi;
use std::boxed::Box;
use std::io;
use std::string::String;
use std::string::ToString;

error_chain! {
    links {
        Ethabi(ethabi::Error, ethabi::ErrorKind);
    }

    foreign_links {
        Io(io::Error);
        //Docopt(docopt::Error);
        //Hex(hex::FromHexError);
    }
}
