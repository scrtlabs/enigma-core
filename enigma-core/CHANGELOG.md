### Version 0.3.0

#### Breaking Changes

* Upgrading to use Rust SGX SDK **v1.0.9**
* Adding ability to revert state
* `enigma-types` is now `no-std` by default. The motivation is that cargo features are almost exclusively additive, which caused unused crates to be downloaded when compiling it for `sgx`.
* `gas limit` is now part of the information that is used when signing task success/failure. This allows to verify that the worker cannot (maliciously) cause task failure by giving the enclave a low `gas limit`.
* changing sealing policy to `SGX_KEYPOLICY_MRSIGNER`.

#### Bug Fixes

* The length field in serialization of multiple values for hashing is now always a `u64` independent of the platform.
* Now the state is rebuilt if it was updated by others after PTT
* Storing of updated state and delta is moved to the very end of a computation, which prevents possible inconsistency.
* Now the status returned by _update deltas_ depends on the individual deltas status.

#### Enhancement

* Adding retries for getting the attestation report from the proxy server. The number of retries may be obtained as an input, otherwise the default number is used.


