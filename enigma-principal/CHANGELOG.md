### Version 0.3.0

#### Breaking Changes

* Upgrading to use Rust SGX SDK **v1.0.9**
* `enigma-types` is now `no-std` by default. The motivation is that cargo features are almost exclusively additive, which caused unused crates to be downloaded when compiling it for `sgx`.
* Added the ability to add the configuration through environment variables
* Now secret contract addresses may be obtained from Enigma contract by one call instead of two.
* changing sealing policy to `SGX_KEYPOLICY_MRSIGNER`.

#### Enhancement

* Adding retries for getting the attestation report from the proxy server. The number of retries may be obtained as an input, otherwise the default number is used.
