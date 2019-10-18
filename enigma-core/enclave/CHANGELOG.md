### Version 0.3.0

#### Breaking Changes

* Upgrading to use Rust SGX SDK **v1.0.9**
* Adding ability to revert state
* `enigma-types` is now `no-std` by default. The motivation is that cargo features are almost exclusively additive, which caused unused crates to be downloaded when compiling it for `sgx`.
* `gas limit` is now part of the information that is used when signing task success/failure. This allows to verify that the worker cannot (maliciously) cause task failure by giving the enclave a low `gas limit`.
* changing sealing policy to `SGX_KEYPOLICY_MRSIGNER`.

#### Bug Fixes

* The length field in serialization of multiple values for hashing is now always a `u64` independent of the platform.
* Building the state when a computation is executed in a scenario in which the deltas were updated after the epoch has changed.
* Moving storing updated state and delta to the very end of a computation, which prevents possible inconsistency.