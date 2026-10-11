Gem::Specification.new do |s|
  s.name        = 'authfi'
  s.version     = '0.1.0'
  s.summary     = 'AuthFI Ruby SDK'
  s.description = 'JWT validation, RBAC middleware, permission auto-sync for AuthFI'
  s.authors     = ['AuthFI']
  s.homepage    = 'https://github.com/authfi/authfi-ruby-sdk'
  s.license     = 'Apache-2.0'
  s.files       = ['authfi.rb']
  s.required_ruby_version = '>= 3.0'

  # Battle-tested JWT implementation — handles RS256 signature
  # verification and JWKS. We do NOT hand-roll crypto.
  s.add_dependency 'jwt', '~> 2.7'
end
