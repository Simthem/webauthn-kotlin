# Contributing to PQ Vault

Thank you for taking the time. PQ Vault is a fork of
[line/webauthn-kotlin](https://github.com/line/webauthn-kotlin) that took the problem back
to the cryptographic layer, so the areas most in need of scrutiny are the vault format,
the merge logic and the credential provider.

## How to help

- Report a bug or propose a feature in
  [the issue tracker](https://github.com/Simthem/webauthn-kotlin/issues).
- Ask a question there as well.
- Send your work as a
  [pull request](https://github.com/Simthem/webauthn-kotlin/pulls).

## Before opening a pull request

Run the same checks the pipeline runs:

```bash
./gradlew verify
```

That covers the unit tests of both modules and Android Lint. A green run locally is a good
predictor of a green pipeline, and it is faster than waiting for one.

The `vault` module has no Android dependency, which is deliberate: the cryptography, the
file format and the merge are testable on a development machine with no emulator. New
logic in those areas is expected to come with tests that run there.

## Security issues

Do not open a public issue for a vulnerability affecting the vault format, the key
derivation or the credential provider. Report it privately through
[GitHub security advisories](https://github.com/Simthem/webauthn-kotlin/security/advisories/new)
so a fix can ship before the details are public.

## Scope

The `webauthn/` module is the original LY Corporation library, kept intact for reference
and not built into the application. Changes there belong upstream rather than here.

## Licence

The project is Apache 2.0, like the original. By contributing you agree that your work is
published under that licence. There is no separate contributor licence agreement to sign.

## Code of conduct

Contributors are expected to follow [our code of conduct](./CODE_OF_CONDUCT.md).
