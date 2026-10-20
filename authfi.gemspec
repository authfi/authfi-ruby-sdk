Gem::Specification.new do |s|
  s.name        = 'authfi'
  s.version     = '0.2.0'
  s.summary     = 'AuthFI Ruby SDK'
  s.description = 'Access token verification (RS256 and EdDSA) and RBAC checks for AuthFI'
  s.authors     = ['AuthFI']
  s.homepage    = 'https://github.com/authfi/authfi-ruby-sdk'
  s.license     = 'Apache-2.0'
  s.files       = ['authfi.rb']
  s.require_paths = ['.']
  s.required_ruby_version = '>= 3.1'

  # Verification uses the standard library's OpenSSL (RSA and Ed25519), so there
  # is no runtime dependency. The jwt gem signs the RS256 tokens the tests verify.
  s.add_development_dependency 'jwt', '>= 2.7'
  s.add_development_dependency 'minitest', '~> 5.0'
end
