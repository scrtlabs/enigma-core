pub mod primitives;
pub mod dal;

use rocksdb::{ReadOptions, DB};
use hex::{ToHex, FromHex};

use self::primitives::DeltaKey;
use self::dal::{DB, Stype};
use common_u::errors::{DBErr, DBErrKind};

const DELTA_PREFIX: &[u8] = &[1];

pub trait P2PCalls {
    /// return the latest delta for the required address.
    fn get_tip<K, D>(&self, address: &[u8; 32]) -> Result<(K, D),Error>;

    /// return the latest delta for each of the required addresses.
    fn get_tips<K, D>(&self, address_list: &[[u8; 32]]) -> Result<Vec<(K, D)>, Error>;

    /// get a list of all addresses in the DB.
    fn get_all_addresses(&self) -> Result<Vec<[u8; 32]>, Error>;

    /// get the delta of the required address and key.
    fn get_delta<K, D>(&self, key: K) -> D;

    /// get the contract of the required contract.
    fn get_contract(&self, address:  [u8; 32]) -> &[u8];

    /// returns a list of the latest deltas for all addresses.
    fn get_all_tips<K, D>(&self) -> Result<Vec<(K, D)>, Error>;

    /// returns a list of all keys specified with their corresponding deltas.
    fn get_deltas<K, D>(&self, addresses_range: Vec<(K, K)>) -> Result<Vec<K, D>, Error>;
}

impl<'a, K: SplitKey> P2PCalls<&'a K> for DB {

    fn get_tip<K, D>(&self, address: &[u8; 32]) -> Result<(K, D),Error> {
        match self.database.cf_handle(&address.to_hex()) {
            None => Error(Err(DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey, previous: None }.into())),
            Some(cf_key) => {
                let iter = self.prefix_iterator_cf(cf_key, DELTA_PREFIX)?;
                let last_delta = match iter.last() {
                    None => Error(Err(DBErr { command: "get_tip".to_string(), kind: DBErrKind::MissingKey, previous: None }.into())),
                    Some(last) => last
                };
                let dk = DeltaKey::from_split(&address, last_delta.0);
                Ok(dk, last_delta.1)
            }
        }
    }

    fn get_tips<K, D>(&self, address_list: &[[u8; 32]]) -> Result<Vec<(K, D)>, Error> {
        let deltas_list = Vec::new();
        // todo: how will we know if there was an error??
        for address in &address_list {
            deltas_list.push(self.get_tip(&address)?);
        }
        Ok(deltas_list)
    }

    fn get_all_addresses(&self) -> Result<Vec<[u8; 32]>, Error> {
        // get a list of all CF's (addresses) in our DB
        let mut cf_list = DB::list_cf(&opts, &self.location)?;
        match cf_list.len() {
            // list_cf returns "Default" as the first CF,
            // so we remove it if we have elements other than that in the DB.
            l if l > 1 => cf_list.remove(0),
            _ => Error(Err(DBErr { command: "get_all_addresses".to_string(), kind: DBErrKind::MissingKey, previous: None }.into())),
        }
        // convert all addresses from strings to slices.
        Ok(cf_list.map(|address_str| {
            let mut address = [0u8; 32];
            address.copy_from_slice(&address_str.from_hex()?[..]);
            address
        }))
    }

    fn get_delta<K, D>(&self, key: K) -> D {self.read(&key)}

    fn get_contract(&self, address: [u8; 32]) -> &[u8] {
        let key = DeltaKey{hash: address, key_type: Stype::ByteCode};
        self.read(&key)
    }

    fn get_all_tips<K, D>(&self) -> Result<Vec<(K, D)>, Error> {
        let address_list = self.get_all_addresses()?;
        Ok(self.get_tips(&address_list)?)
    }

    // input: addresses_range : Vec<Tuple(K, K)> where K is usually a DeltaKey.
    // output: all keys & values from the first key (included!) up to the second key (not included!!)
    fn get_deltas<K, D>(&self, addresses_range: Vec<(K, K)>) -> Result<Vec<K, D>, Error> {
        // a vector for the output values which will consist of tuples: (key: K, value/delta: D)
        let mut deltas_list = Vec::new();
        // for each tuple in the input
        for address_rng in addresses_range.iter() {
            // todo think of a generic way to compare the addresses
            // compare the addresses are similar
            assert_eq!(&address_rng.0.hash, &address_rng.1.hash);
            // convert the key to the needed rocksdb representation
            address_rng.0.as_split(|from_hash, from_key| {
                // make sure the address exists as a CF in the DB
                match self.cf_handle(&from_hash) {
                    None => Err(DBErr { command: "read".to_string(), kind: DBErrKind::MissingKey, previous: None }.into()),
                    Some(cf_key) => {
                        // if exists, extract the second key for the range.
                        address_rng.1.as_split(|hash_to, to_key| {
                            let mut read = ReadOptions::default();
                            // add the key as an upper bound
                            // (all elements up to this key, not included!!)
                            read.set_iterate_upper_bound(&to_key);
                            // build an iterator which will iterate from the first key
                            let mut iter = DBIterator::new_cf(&self, cf_key.clone(), &read, IteratorMode::From(&from_key, Direction::Forward))?;
                            mapped_iter = iter.map(|(key, val)| {
                                // creating from the string of the address and the
                                // key of each result in the iterator a K type.
                                // from_split returns a result and therefore will return
                                // an error in case that it won't be able to create the key.
                                (K::from_split(hash_to, key)?, val)
                            });
                            //add the values received from the iteration
                            // of the input to the output vector.
                            deltas_list.extend(&mapped_iter);
                        })
                    }
                }
            })
        }
        Ok(deltas_list)
    }
}
