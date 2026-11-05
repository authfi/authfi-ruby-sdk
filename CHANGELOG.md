# Changelog

All notable changes to this gem. It follows [Semantic Versioning](https://semver.org): before 1.0 a minor
version may break, but only with an entry here.

## 0.2.0

The first version published to RubyGems. Earlier versions were installed from git.

### Added

- Verification of EdDSA access tokens, which is how AuthFI signs an AI agent's token, beside RS256.
- Key discovery from the issuer: the key set is read from the `jwks_uri` in
  `<issuer>/.well-known/openid-configuration` (falling back to `oauth-authorization-server`), and the issuer in
  the document must match the one you configured.

### Changed

- **Verification is strict.** A token is accepted only when its `typ` is `at+jwt`, its `iss` matches exactly, its
  `aud` contains an audience you configured (with none configured, every token is refused) and `exp` is present.
  ID tokens and tokens minted for another API are refused. **Breaking** for code that relied on the earlier,
  looser checks.
- Keys with private members, `use=enc`, an `alg` that does not match the key, or an RSA modulus under 2048 bits
  are refused. An unknown `kid` refetches the key set at most once every 30 seconds.
- Verification uses the standard library's OpenSSL for RS256 and EdDSA, so the gem has no runtime dependencies.
  The `jwt` gem is a development dependency only.
- The client no longer prints its API key (`inspect`, `pp`, `Marshal`), and a refusal never carries the token.
- Ruby 3.1 or later is required.
