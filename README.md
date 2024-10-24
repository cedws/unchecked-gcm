# unchecked-gcm

Modified version of AES-GCM implementation in `crypto/cipher` to allow
decryption without/before authentication tag verification. This is **insecure** and
exists only for compatibility with insecure systems.

An additional `Tag() [gcmTagSize]byte` method is added to enable arbitrary tag generation for the processed ciphertext at any point.

`Verify([]byte)` has also been added to enable verification of the tag after decryption.

## License

See header of `gcm.go` for license information.
