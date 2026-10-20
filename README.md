# AuthFI Ruby SDK

Official Ruby SDK for [AuthFI](https://authfi.io) — the identity control plane.

It verifies the access tokens AuthFI issues, for people and for AI agents, and checks
roles and permissions on the claims.

## Install

The SDK is installed from git. It is not published to RubyGems yet.

```ruby
# Gemfile — pin ref: to a commit so installs are reproducible
gem 'authfi', git: 'https://github.com/authfi/authfi-ruby-sdk.git', ref: '<commit>'
```

Requires Ruby 3.1 or later. It has no runtime dependencies.

## Quick Start (Rails)

```ruby
# config/initializers/authfi.rb
AUTH = AuthFI.new(
  tenant: 'acme',
  issuer: 'https://acme.authfi.io',  # your project's issuer
  audience: 'app_xxxxxxxx'           # the client id(s) your API accepts
)

# app/controllers/application_controller.rb
class ApplicationController < ActionController::API
  before_action :authenticate!

  private

  def authenticate!
    @current_user = AUTH.authenticate(request)
  rescue AuthFI::Error => e
    render json: { error: 'unauthorized' }, status: e.status
  end
end

# app/controllers/users_controller.rb
class UsersController < ApplicationController
  before_action -> { AUTH.require_permissions!(@current_user, 'read:users') }

  def index
    render json: User.all
  end
end
```

## Token verification

```ruby
claims = AUTH.verify_token(token)
# claims['sub'], claims['email'], claims['roles'], claims['permissions']
```

`verify_token` accepts a token only when all of these hold. Otherwise it raises
`AuthFI::Error` (status 401) with a fixed message that never contains the token.

- The signature verifies against the project's published keys. The keys are found by
  discovery: the SDK reads `<issuer>/.well-known/openid-configuration` and fetches the
  `jwks_uri` it names. RS256 (people, machine clients) and EdDSA (AI agents) are accepted.
- The header `typ` is `at+jwt`. An ID token is refused.
- `iss` equals the issuer exactly.
- `aud` contains one of the configured audiences. With no `audience:` configured, every
  token is refused. The issuer itself, and anything under it such as `<issuer>/mcp`, is
  refused as an audience.
- `exp` is present and in the future, with `leeway:` seconds of clock skew (default 60).
- `sub` is present.

A custom domain is set with `issuer:`. Without it the issuer is `https://<tenant>.authfi.io`.
The keys are cached for `jwks_ttl` seconds (default 300). A token naming an unknown key
refetches them at most once every 30 seconds.

## Roles and permissions

```ruby
AUTH.require_permissions!(claims, 'read:users')  # all of them, else 403
AUTH.require_role!(claims, 'admin', 'editor')    # any of them, else 403
```

Any Rack app can use `verify_token` with the `Authorization` header it already reads.

## Running tests

```bash
gem install jwt
gem install minitest -v '~> 5.0'
ruby test_authfi.rb
```

## License

Apache-2.0
