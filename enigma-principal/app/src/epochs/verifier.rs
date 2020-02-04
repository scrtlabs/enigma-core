use std::{
    fs::{self, File},
    io::prelude::*,
    ops::Deref,
    path::PathBuf,
    sync::Mutex,
};
use std::clone::Clone;
use std::sync::MutexGuard;
use std::mem::replace;

use failure::Error;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use web3::types::U256;

use enigma_tools_m::keeper_types::EPOCH_CAP;

use common_u::errors::{EpochStateIOErr, EpochStateTransitionErr, EpochStateUndefinedErr};
use epochs::epoch_types::{ConfirmedEpochState, EPOCH_STATE_UNCONFIRMED, SignedEpoch};
use esgx::general::{EPOCH_DIR, EPOCH_FILE};

#[derive(Debug)]
pub struct EpochVerifier {
    pub epoch_list: Mutex<Vec<SignedEpoch>>,
    state_path: PathBuf,
}

impl EpochVerifier {
    pub fn new(mut state_path: PathBuf) -> Result<Self, Error> {
        state_path.push(EPOCH_DIR);
        if !state_path.exists() {
            fs::create_dir_all(&state_path)?;
        }
        state_path.push(EPOCH_FILE);
        Self::create_from_path(state_path)
    }

    /// create an EpochVerifier object given the path from which we retrieve
    /// the epoch states and we use the cap amount of epochs as well to handle backwards.
    fn create_from_path(state_path: PathBuf) -> Result<EpochVerifier, Error> {
        let signed_epochs = match File::open(&state_path) {
            Ok(mut f) => {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                let mut des = Deserializer::new(&buf[..]);
                let mut data: Vec<SignedEpoch> = Deserialize::deserialize(&mut des).unwrap_or_default();
                trace!("Found epoch state list");
                if EPOCH_CAP < data.len() {
                    return Err(EpochStateIOErr { message: format!("The SignedEpoch entries exceed the cap: {}", EPOCH_CAP) }.into());
                }
                let mut capped_data = Vec::with_capacity(EPOCH_CAP);
                capped_data.append(&mut data);
                capped_data
            }
            Err(_) => {
                trace!("No existing epoch state");
                vec![]
            }
        };
        let epoch_list = Mutex::new(signed_epochs);
        Ok(EpochVerifier { epoch_list, state_path})
    }

    /// Lock the `EpochState` list `Mutex`, or wait and retry
    pub fn lock_guard_or_wait(&self) -> Result<MutexGuard<Vec<SignedEpoch>>, Error> {
         self.epoch_list.lock().
             map_err( |e| { EpochStateIOErr { message: format!("Cannot lock EpochState: {:?}", e), }.into() })
    }

    /// Checks if the latest `EpochState` is unconfirmed
    pub fn is_last_unconfirmed(&self) -> Result<bool, Error> {
        let guard = self.lock_guard_or_wait()?;
        if guard.is_empty() {
            drop(guard);
            return Ok(false);
        }
        let last = guard.iter().last();
        //TODO: why borrow checker fails here
        let epoch = last.ok_or(EpochStateUndefinedErr{})?;

        let is_unconfirmed = match &epoch.confirmed_state {
            Some(_) => false,
            None => true,
        };
        Ok(is_unconfirmed)
    }

    /// Return a list of all confirmed `SignedEpoch`s
    pub fn get_all_confirmed(&self) -> Result<Vec<SignedEpoch>, Error> {
        let guard = self.lock_guard_or_wait()?;
        let mut result: Vec<SignedEpoch> = vec![];
        for epoch in guard.iter() {
            if epoch.confirmed_state.is_some() {
                result.push(epoch.clone());
            }
        }
        Ok(result)
    }

    /// Returns the confirmed `SignedEpoch` for the epoch of the given block number
    /// # Arguments
    ///
    /// * `block_number` - A block number in the desired epoch
    pub fn get_confirmed_by_block_number(&self, block_number: U256) -> Result<SignedEpoch, Error> {
        let mut result: Option<&SignedEpoch> = None;
        let epochs = self.get_all_confirmed()?;
        for epoch in epochs.iter() {
            let confirmed: &ConfirmedEpochState = epoch.confirmed_state.as_ref().unwrap();
            if confirmed.ether_block_number <= block_number {
                result = Some(epoch);
            }
        }
        match result {
            Some(epoch_state) => Ok(epoch_state.clone()),
            None => {
                Err(EpochStateTransitionErr { current_state: EPOCH_STATE_UNCONFIRMED.to_string() }.into())
            }
        }
    }

    /// Returns the most recent `SignedEpoch` stored in memory
    /// # Arguments
    ///
    /// * `exclude_unconfirmed` - Exclude any unconfirmed state
    pub fn last(&self, exclude_unconfirmed: bool) -> Result<SignedEpoch, Error> {
        let guard = self.lock_guard_or_wait()?;
        let mut epoch_state_val: Option<SignedEpoch> = None;
        for epoch_state in guard.iter().rev() {
            if (exclude_unconfirmed && epoch_state.confirmed_state.is_some()) || !exclude_unconfirmed {
                epoch_state_val = Some(epoch_state.clone());
                break;
            }
        }
        drop(guard);
        Ok(epoch_state_val.ok_or(EpochStateUndefinedErr{})?)
    }

    #[logfn(DEBUG)]
    fn store_signed_epoch(&self) -> Result<(), Error> {
        let guard = self.lock_guard_or_wait()?;
        let epoch_list = guard.deref().clone();
        drop(guard);
        if epoch_list.is_empty() {
            return Ok(fs::remove_file(&self.state_path).unwrap_or_else(|_| trace!("No epoch state file to remove")));
        }
        let mut file = File::create(&self.state_path).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        let mut buf = Vec::new();
        epoch_list.serialize(&mut Serializer::new(&mut buf)).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        file.write_all(&buf).
            map_err(|e| EpochStateIOErr { message: format!("Unable to write the EpochState list: {}", e)})?;
        trace!("Saved epoch state list {:?} to {:?}", epoch_list, &self.state_path);
        Ok(())
    }

    /// Empty the `SignedEpoch` list both on memory and disk
    pub fn reset(&self) -> Result<(), Error> {
        let mut guard = self.lock_guard_or_wait()?;
        replace(&mut *guard, vec![]);
        drop(guard);
        self.store_signed_epoch()
    }

    /// Append a new unconfirmed `SignedEpoch` to the list and persist to disk
    /// # Arguments
    ///
    /// * `signed_epoch` - The unconfirmed `SignedEpoch` to append
    pub fn append_unconfirmed(&self, signed_epoch: SignedEpoch) -> Result<(), Error> {
        if self.is_last_unconfirmed()? {
            bail!("An unconfirmed EpochState must be appended after a confirmed");
        }
        let mut guard = self.lock_guard_or_wait()?;
        // Remove the first item of the list an shift left if the capacity is reached
        if guard.len() == EPOCH_CAP {
            let removed_epoch = guard.remove(0);
            trace!("Removed first EpochState of capped list: {:?}", removed_epoch);
        }
        guard.push(signed_epoch);
        drop(guard);
        self.store_signed_epoch()
    }

    /// Confirm the last unconfirmed `SignedEpoch`
    /// # Arguments
    ///
    /// * `signed_epoch` - The confirmed `SignedEpoch`
    pub fn confirm_last(&self, signed_epoch: SignedEpoch) -> Result<(), Error> {
        let mut guard = self.lock_guard_or_wait()?;
        if let Some(last) = guard.last_mut() {
            if last.confirmed_state.is_some() {
                bail!("Last EpochState already confirmed: {:?}", last);
            }
            *last = signed_epoch;
        } else {
            bail!("Cannot confirm the last EpochState of an empty list");
        }
        drop(guard);
        self.store_signed_epoch()
    }
}