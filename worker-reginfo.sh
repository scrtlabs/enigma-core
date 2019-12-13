#!/usr/bin/env bash

cd enigma-core
make
cd app
cargo test get_info_for_contract_tests -- --nocapture
