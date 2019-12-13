#!/usr/bin/env bash

cd enigma-principal
make
cd app
cargo test get_info_for_contract_tests -- --nocapture
