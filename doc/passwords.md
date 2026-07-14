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

## Build and isolated test

The module uses the DGD extension ABI declared by `src/lpc_ext.h`; this branch
retains the repository's active extension version 1.6. Build from a clean
checkout with:

```sh
make -C src crypto
file crypto.1.6
ldd crypto.1.6
```

The build requires an OpenSSL release that provides `EVP_PBE_scrypt()`
(OpenSSL 1.1.1 or later). The compiler command is printed by `make` and links
the module with `-lcrypto`.

`test/password_scrypt.c` is an isolated DGD test object. To reproduce the
runtime checks without installing the module over an active copy:

1. Copy a Cloud Server source tree and its configuration to a temporary
   directory.
2. Bind its listener to loopback on unused ports and point the configuration's
   crypto module entry at the absolute path of the newly built `crypto.1.6`.
3. Copy `test/password_scrypt.c` into the temporary source tree as
   `/usr/EL/sys/password_scrypt_test.c`.
4. Add a temporary compile call for that object to `/usr/EL/initd.c`.
5. Start DGD from source with the temporary configuration only.
6. From the temporary administrator code tool, evaluate:

   ```text
   "/usr/EL/sys/password_scrypt_test"->run()
   ```

7. Require `all_checks` to be true, inspect only the returned timing and count
   fields, then stop the temporary process with ordinary `shutdown`.

The harness covers correct and incorrect passwords, different salts, salt and
key tampering, unknown version and algorithm, modified N/r/p, truncated and
trailing records, invalid hex, the empty-password policy, the 128-byte limit,
over-limit rejection, repeated hashing, generated kfun macros, and timing. It
does not return or print a password, salt, derived key, or encoded record. Do
not use a snapshot, state restore, hotboot, production listener, or production
account data for this test.
