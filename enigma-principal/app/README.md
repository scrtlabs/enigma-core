## App Structure

this folder consists of all the untrusted KM functionality.

it's divided into 5 folders:

##cli 

consists of the scripts called by `main.rs` in the rebooting of the KM and the handling of the 
cli options.


##boot_network
 
 Consists of the functionality the boots up the KM.
 The `principal_manager` which creates the 2 threads which handle the functionality of the KM, which consist of 
 the watching blocks thread that is located in `principal_utils.rs` file which counts the number of blocks until the end of the epoch and is in charge of 
 evaluating a new random seed which will define the new epoch and the second thread which handles the json rpc server
 which is located in the `keys_provider_http.rs` file.
 `deploy_scripts` consists of other functionality which is used to run tests while running idle.
 
 ## common_u
 
 consists of the joint methods to all of the untrusted functionality. In our case it consists only of the custom errors.
 
 ## epoch_u
 
 Consists of all scripts which are in charge of handling the epoch data.
 There are 3 structs which are provided:
 `epoch_state`- holds all data which is needed on the untrusted side that defines an epoch which was created in the enclave.
 `epoch_state_manager`- holds a `cap` amount of epochs which can be called upon by workers (cap is defined when booting the network- in the configurations).
 `epoch_provider`- holds all what's needed in order to create a new epoch (the eid of the enclave and an enigma-contract object which can communicate with the contract on ethereum) and the epoch_state manager.
 
 ## esgx
 
 all the ecall functionality that calls the trusted side. 
 `epoch_keeper_u.rs` consists of setting the worker params which creates the new epoch - evaluates a new seed, and stores all active workers with it,
 to have all necessary data for running the worker selection algorithm and confirm the keys are given to the right worker.
 `equote` - similar to the enigma-core, all the functionality that registers a worker and evaluates a key pair for the encalve.
 `key_keeper_u.rs` consists of the functionality on the untrusted side which provides the worker with the state keys of the contracts that he is in charge of in the current (or in inside the cap) 
 epoch.