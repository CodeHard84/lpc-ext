# Password hashing

The crypto module exposes three fixed-policy password functions:

```text
string password_hash(string password)
int password_verify(string password, string encoded)
int password_hash_valid(string encoded)
```

`password_hash()` creates a new record. `password_verify()` returns true only
when the supplied password matches a valid record. `password_hash_valid()`
performs strict structural validation without running the password KDF.
Malformed, truncated, unknown, or parameter-modified records return false from
the validation and verification functions.

Records use this ASCII format:

```text
$EL2$scrypt$32768$8$1$<32 lowercase salt hex digits>$<64 lowercase key hex digits>
```

The implementation uses OpenSSL `EVP_PBE_scrypt()` with N=32768, r=8, p=1, a
16-byte `RAND_bytes()` salt, a 32-byte derived key, and a 64 MiB `maxmem`
limit. Verification accepts only this exact parameter set, so record contents
cannot select unbounded CPU or memory work. Password inputs must contain 1 to
128 bytes.

Derived keys are compared with `CRYPTO_memcmp()`. Native salt and derived-key
buffers are cleared with `OPENSSL_cleanse()` after use. Hash creation failures
raise a generic runtime error; an incorrect password and a malformed record
return false without revealing which check failed.

Scrypt is intentionally CPU- and memory-intensive and runs synchronously in
the DGD driver task. At these parameters one operation requires roughly 32 MiB
for the scrypt working set, plus OpenSSL overhead. Deployments should benchmark
login latency on their actual host before enabling the module.

Password records are one-way hashes. Passwords are not encrypted or
recoverable, and these functions do not protect plaintext passwords while they
are being transported to the application.
