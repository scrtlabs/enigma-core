extern crate principal;
extern crate web3;

#[cfg(test)]
mod tests {
    use principal::ethchain::EnigmaContract;
    use principal::ethchain::Ledger;
    use web3::Web3;
    use web3::transports::Http;
    use web3::types::Address;
    use web3;

    fn setup() -> (web3::transports::EventLoopHandle, Web3<Http>)
    {
        let (_eloop, http) = web3::transports::Http::new("http://localhost:9545").unwrap();
        let w3 = web3::Web3::new(http);
        (_eloop, w3)
    }

    #[test]
    fn it_registers()
    {
        let (_, w3) = setup();
        let contract_address: Address = "eec918d74c746167564401103096d45bbd494b74"
            .parse()
            .unwrap();
        let contract = EnigmaContract::new(w3, contract_address);
        let tx = contract.register();
        assert!(tx.len() > 0);
    }

    #[test]
    fn it_watch_blocks()
    {
        let (eloop, w3) = setup();
        let ledger = Ledger::new(w3);
        ledger.watch_blocks(eloop, 5, 3);
    }
}
