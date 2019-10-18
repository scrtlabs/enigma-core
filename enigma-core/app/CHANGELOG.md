### Version 0.3.0

#### Breaking Changes

* Upgrading to use Rust SGX SDK v1.0.9
* Adding retries for getting the attestation report from the proxy server. The number of retries may be obtained as an input, otherwise the default number is used.
* `enigma-types` is now `no-std` by default. The motivation is that cargo features are almost exclusively additive, which caused unused crates to be downloaded when compiling it for `sgx`.

#### Bug Fixes

* Now the status returned by _update deltas_ depends on the individual deltas status