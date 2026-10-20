require 'minitest/autorun'
require 'minitest/mock'
require_relative 'authfi'
require 'json'
require 'base64'
require 'jwt'
require 'openssl'
require 'socket'
require 'pp'
require 'stringio'
require 'yaml'

# Tokens are signed here with the jwt gem (RS256) and with OpenSSL directly
# (EdDSA), both independent of the SDK's own verification code. Discovery and
# the JWKS are served by an in-memory fake that answers 404 for every URL the
# platform does not serve, so a wrong URL fails exactly as it does live.

ISSUER = 'https://acme.authfi.io'.freeze
JWKS_URI = 'https://acme.authfi.io/oauth/jwks'.freeze
AUDIENCE = 'app_acme'.freeze

module Keys
  RSA_KEY = OpenSSL::PKey::RSA.generate(2048)
  ATTACKER_KEY = OpenSSL::PKey::RSA.generate(2048)
  SMALL_RSA = OpenSSL::PKey::RSA.generate(1024)
  ED_KEY = OpenSSL::PKey.generate_key('ED25519')
  ATTACKER_ED = OpenSSL::PKey.generate_key('ED25519')

  def self.b64(bin)
    Base64.urlsafe_encode64(bin, padding: false)
  end

  def self.rsa_jwk(key, kid, extra = {})
    { 'kty' => 'RSA', 'kid' => kid, 'use' => 'sig', 'alg' => 'RS256',
      'n' => b64(key.n.to_s(2)), 'e' => b64(key.e.to_s(2)) }.merge(extra)
  end

  # The 32 public key bytes: the tail of the SubjectPublicKeyInfo DER.
  def self.raw_public(key)
    key.respond_to?(:raw_public_key) ? key.raw_public_key : key.public_to_der[-32..]
  end

  def self.ed_jwk(key, kid, extra = {})
    { 'kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => kid, 'use' => 'sig',
      'x' => b64(raw_public(key)) }.merge(extra)
  end

  def self.jwks(extra_keys = [])
    { 'keys' => [rsa_jwk(RSA_KEY, 'rs-1'), ed_jwk(ED_KEY, 'ed-1')] + extra_keys }
  end

  def self.rs256(claims, key: RSA_KEY, kid: 'rs-1', typ: 'at+jwt')
    header = { kid: kid }
    header[:typ] = typ unless typ.nil?
    JWT.encode(claims, key, 'RS256', header)
  end

  # RS256 signed by OpenSSL directly, for claims or keys the jwt gem refuses to encode.
  def self.hand_rs256(claims, key:, kid: 'rs-1')
    h = b64({ alg: 'RS256', typ: 'at+jwt', kid: kid }.to_json)
    p = b64(claims.to_json)
    "#{h}.#{p}.#{b64(key.sign(OpenSSL::Digest.new('SHA256'), "#{h}.#{p}"))}"
  end

  def self.eddsa(claims, key: ED_KEY, kid: 'ed-1', typ: 'at+jwt', alg: 'EdDSA')
    header = { 'alg' => alg, 'kid' => kid }
    header['typ'] = typ unless typ.nil?
    h = b64(header.to_json)
    p = b64(claims.to_json)
    "#{h}.#{p}.#{b64(key.sign(nil, "#{h}.#{p}"))}"
  end

  def self.claims(overrides = {})
    { 'sub' => 'usr_123', 'iss' => ISSUER, 'aud' => [AUDIENCE], 'tenant_id' => 't1',
      'roles' => %w[admin editor], 'permissions' => %w[read:users write:users],
      'iat' => Time.now.to_i, 'exp' => Time.now.to_i + 3600 }.merge(overrides)
  end
end

# A fake of the platform's HTTP surface: only the listed URLs exist.
class FakeWeb
  attr_reader :calls

  def initialize(routes)
    @routes = routes
    @calls = []
  end

  def call(url)
    @calls << url
    r = @routes[url]
    r = r.call if r.respond_to?(:call)
    r ? [200, r.is_a?(String) ? r : r.to_json] : [404, 'not found']
  end
end

def discovery(extra = {})
  { 'issuer' => ISSUER, 'jwks_uri' => JWKS_URI }.merge(extra)
end

def platform(jwks: Keys.jwks, doc: discovery, doc_path: 'openid-configuration')
  FakeWeb.new("#{ISSUER}/.well-known/#{doc_path}" => doc, JWKS_URI => jwks)
end

def client(**opts)
  AuthFI.new(**{ tenant: 'acme', audience: AUDIENCE }.merge(opts))
end

def verify_with(web, token, **opts)
  auth = client(**opts)
  auth.stub(:http_get, ->(url) { web.call(url) }) { auth.verify_token(token) }
end

class TestDiscovery < Minitest::Test
  def test_default_jwks_comes_from_discovery_not_a_built_url
    web = platform
    claims = verify_with(web, Keys.rs256(Keys.claims))
    assert_equal 'usr_123', claims['sub']
    assert_equal ["#{ISSUER}/.well-known/openid-configuration", JWKS_URI], web.calls
  end

  def test_falls_back_to_oauth_authorization_server
    web = platform(doc_path: 'oauth-authorization-server')
    assert_equal 'usr_123', verify_with(web, Keys.rs256(Keys.claims))['sub']
  end

  def test_refuses_discovery_whose_issuer_is_another
    web = platform(doc: discovery('issuer' => 'https://evil.example.com'))
    err = assert_raises(AuthFI::Error) { verify_with(web, Keys.rs256(Keys.claims)) }
    assert_equal 401, err.status
  end

  def test_refuses_discovery_without_a_jwks_uri
    web = platform(doc: { 'issuer' => ISSUER })
    assert_raises(AuthFI::Error) { verify_with(web, Keys.rs256(Keys.claims)) }
  end

  def test_refuses_plain_http_jwks_uri_even_when_it_answers
    http_uri = 'http://acme.authfi.io/oauth/jwks'
    web = FakeWeb.new(
      "#{ISSUER}/.well-known/openid-configuration" => discovery('jwks_uri' => http_uri),
      http_uri => Keys.jwks
    )
    assert_raises(AuthFI::Error) { verify_with(web, Keys.rs256(Keys.claims)) }
  end

  def test_a_non_200_answer_is_never_used_even_when_its_body_is_valid
    auth = client
    answers = lambda do |url|
      url.end_with?('openid-configuration') ? [200, discovery.to_json] : [500, Keys.jwks.to_json]
    end
    assert_raises(AuthFI::Error) { auth.stub(:http_get, answers) { auth.verify_token(Keys.rs256(Keys.claims)) } }
  end

  def test_a_failed_fetch_is_not_cached
    up = false
    web = FakeWeb.new(
      "#{ISSUER}/.well-known/openid-configuration" => -> { up ? discovery : nil },
      JWKS_URI => -> { up ? Keys.jwks : nil }
    )
    auth = client
    token = Keys.rs256(Keys.claims)
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      assert_raises(AuthFI::Error) { auth.verify_token(token) }
      up = true
      assert_equal 'usr_123', auth.verify_token(token)['sub']
    end
  end

  def test_custom_issuer_drives_discovery
    iss = 'https://login.example.com'
    web = FakeWeb.new(
      "#{iss}/.well-known/openid-configuration" => { 'issuer' => iss, 'jwks_uri' => "#{iss}/keys" },
      "#{iss}/keys" => Keys.jwks
    )
    token = Keys.rs256(Keys.claims('iss' => iss))
    assert_equal 'usr_123', verify_with(web, token, issuer: iss)['sub']
  end

  def test_issuer_must_be_https_without_path_or_trailing_slash
    ['http://acme.authfi.io', 'https://acme.authfi.io/', 'https://acme.authfi.io/x', 'https://a.io?x=1', 'nonsense'].each do |bad|
      assert_raises(ArgumentError, bad) { client(issuer: bad) }
    end
    client(issuer: 'http://localhost:8080') # loopback is allowed
  end

  def test_jwks_is_cached_between_calls
    web = platform
    auth = client
    token = Keys.rs256(Keys.claims)
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      3.times { auth.verify_token(token) }
    end
    assert_equal 2, web.calls.length
  end

  def test_unknown_kid_causes_at_most_one_refetch_per_window
    web = platform
    auth = client
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      auth.verify_token(Keys.rs256(Keys.claims))
      10.times do |i|
        assert_raises(AuthFI::Error) { auth.verify_token(Keys.rs256(Keys.claims, kid: "invented-#{i}")) }
      end
    end
    assert_equal 2, web.calls.length, 'invented kids must not refetch the JWKS'
  end

  def test_unknown_kid_refetches_once_after_the_window_to_pick_up_rotation
    web = platform
    auth = client
    rotated = Keys.jwks([Keys.rsa_jwk(Keys::ATTACKER_KEY, 'rs-2')])
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      auth.verify_token(Keys.rs256(Keys.claims))
      web.instance_variable_get(:@routes)[JWKS_URI] = rotated
      later = Time.now + AuthFI::JWKS_MIN_REFETCH_SECONDS + 1
      Time.stub(:now, later) do
        token = Keys.rs256(Keys.claims('exp' => later.to_i + 60, 'iat' => later.to_i), key: Keys::ATTACKER_KEY, kid: 'rs-2')
        assert_equal 'usr_123', auth.verify_token(token)['sub']
      end
    end
  end

  def test_real_http_follows_the_discovery_document
    server, port = serve do |path|
      case path
      when '/.well-known/openid-configuration' then [200, discovery('issuer' => "http://127.0.0.1:#{@port}", 'jwks_uri' => "http://127.0.0.1:#{@port}/jwks").to_json]
      when '/jwks' then [200, Keys.jwks.to_json]
      else [404, '']
      end
    end
    iss = "http://127.0.0.1:#{port}"
    token = Keys.rs256(Keys.claims('iss' => iss))
    assert_equal 'usr_123', client(issuer: iss).verify_token(token)['sub']
    assert_match(%r{\Aauthfi-ruby/\d+\.\d+\.\d+ \(ruby }, @seen['user-agent'])
    assert_equal 'identity', @seen['accept-encoding']
  ensure
    server&.close
  end

  def test_real_http_does_not_follow_redirects
    server, port = serve do |path|
      path == '/.well-known/openid-configuration' ? [302, ''] : [404, '']
    end
    iss = "http://127.0.0.1:#{port}"
    assert_raises(AuthFI::Error) { client(issuer: iss).verify_token(Keys.rs256(Keys.claims('iss' => iss))) }
  ensure
    server&.close
  end

  def test_real_http_refuses_an_oversize_document_even_when_it_is_valid
    server, port = serve do |path|
      base = "http://127.0.0.1:#{@port}"
      case path
      when '/.well-known/openid-configuration'
        [200, { 'issuer' => base, 'jwks_uri' => "#{base}/jwks", 'pad' => 'x' * (AuthFI::MAX_DOC_BYTES + 1) }.to_json]
      when '/jwks' then [200, Keys.jwks.to_json]
      else [404, '']
      end
    end
    iss = "http://127.0.0.1:#{port}"
    assert_raises(AuthFI::Error) { client(issuer: iss).verify_token(Keys.rs256(Keys.claims('iss' => iss))) }
  ensure
    server&.close
  end

  def test_the_read_stops_at_the_cap_instead_of_waiting_for_the_rest
    srv = TCPServer.new('127.0.0.1', 0)
    port = srv.addr[1]
    Thread.new do
      sock = srv.accept
      while (l = sock.gets) && l != "\r\n"; end
      sock.write("HTTP/1.1 200 OK" + "\r\n" + "Content-Length: 50000000" + "\r\n" + "\r\n" + ('x' * (AuthFI::MAX_DOC_BYTES + 1000)))
      sleep 15
    rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::EPIPE
      nil
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    err = assert_raises(AuthFI::Error) { client.send(:http_get, "http://127.0.0.1:#{port}/") }
    assert_equal 'Fetch failed: response too large', err.message
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
  ensure
    srv&.close
  end

  def test_a_peer_that_drips_its_headers_is_cut_off_by_the_total_deadline
    srv = TCPServer.new('127.0.0.1', 0)
    port = srv.addr[1]
    Thread.new do
      sock = srv.accept
      sock.write('HTTP/1.1 200 OK' + "\r\n")
      30.times { sock.write('X'); sleep 0.2 }
    rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::EPIPE
      nil
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    err = assert_raises(AuthFI::Error) { client(fetch_timeout: 0.6).send(:http_get, "http://127.0.0.1:#{port}/") }
    assert_equal 'Fetch failed: timed out', err.message
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 4
  ensure
    srv&.close
  end

  def test_a_non_loopback_http_jwks_uri_is_refused_even_for_a_loopback_issuer
    iss = 'http://127.0.0.1:8080'
    web = FakeWeb.new(
      "#{iss}/.well-known/openid-configuration" => { 'issuer' => iss, 'jwks_uri' => 'http://example.com/jwks' },
      'http://example.com/jwks' => Keys.jwks
    )
    err = assert_raises(AuthFI::Error) { verify_with(web, Keys.rs256(Keys.claims('iss' => iss)), issuer: iss) }
    assert_equal 'Discovery document has no valid jwks_uri', err.message
  end

  def test_a_plain_http_loopback_jwks_uri_is_refused_for_a_remote_https_issuer
    local = 'http://127.0.0.1:9/jwks'
    web = FakeWeb.new(
      "#{ISSUER}/.well-known/openid-configuration" => discovery('jwks_uri' => local),
      local => Keys.jwks
    )
    err = assert_raises(AuthFI::Error) { verify_with(web, Keys.rs256(Keys.claims)) }
    assert_equal 'Discovery document has no valid jwks_uri', err.message
  end

  def test_a_discovery_answer_that_is_not_an_object_falls_back
    web = FakeWeb.new(
      "#{ISSUER}/.well-known/openid-configuration" => [],
      "#{ISSUER}/.well-known/oauth-authorization-server" => discovery,
      JWKS_URI => Keys.jwks
    )
    assert_equal 'usr_123', verify_with(web, Keys.rs256(Keys.claims))['sub']
  end

  private

  # A throwaway loopback HTTP server. The block maps a path to [status, body].
  def serve(&handler)
    server = TCPServer.new('127.0.0.1', 0)
    @port = server.addr[1]
    Thread.new do
      loop do
        sock = server.accept
        line = sock.gets.to_s
        while (l = sock.gets) && l != "\r\n"
          (@seen ||= {})[l.split(':', 2)[0].downcase] = l.split(':', 2)[1].to_s.strip
        end
        status, body, extra = handler.call(line.split(' ')[1])
        loc = status == 302 ? "Location: http://127.0.0.1:#{@port}/elsewhere\r\n" : ''
        loc += extra.to_s
        sock.write("HTTP/1.1 #{status} X\r\n#{loc}Content-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        sock.close
      rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::EPIPE
        break
      end
    end
    [server, @port]
  end
end

class TestAlgorithms < Minitest::Test
  def test_accepts_rs256_user_token
    claims = verify_with(platform, Keys.rs256(Keys.claims))
    assert_equal %w[admin editor], claims['roles']
  end

  def test_accepts_eddsa_agent_token
    claims = verify_with(platform, Keys.eddsa(Keys.claims('sub' => 'agt_1', 'aud' => AUDIENCE)))
    assert_equal 'agt_1', claims['sub']
  end

  def test_rejects_eddsa_signed_by_another_key
    token = Keys.eddsa(Keys.claims, key: Keys::ATTACKER_ED)
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_rejects_rs256_signed_by_another_key
    token = Keys.rs256(Keys.claims, key: Keys::ATTACKER_KEY)
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_rejects_tampered_payload
    h, p, s = Keys.rs256(Keys.claims('permissions' => ['read:users'])).split('.')
    forged = JSON.parse(Base64.urlsafe_decode64(p)).merge('permissions' => ['delete:users'])
    assert_raises(AuthFI::Error) { verify_with(platform, "#{h}.#{Keys.b64(forged.to_json)}.#{s}") }
  end

  def test_rejects_none_and_hmac_and_es256
    %w[none HS256 ES256 PS256].each do |alg|
      h = Keys.b64({ alg: alg, typ: 'at+jwt', kid: 'rs-1' }.to_json)
      p = Keys.b64(Keys.claims.to_json)
      err = assert_raises(AuthFI::Error, alg) { verify_with(platform, "#{h}.#{p}.#{Keys.b64('sig')}") }
      assert_equal 'Unsupported token algorithm', err.message, alg
    end
  end

  def test_hmac_signed_with_the_public_key_as_secret_is_refused
    pub = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1').to_json
    token = JWT.encode(Keys.claims, pub, 'HS256', { kid: 'rs-1', typ: 'at+jwt' })
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_rs256_header_with_an_ed25519_key_is_refused
    token = Keys.rs256(Keys.claims, kid: 'ed-1')
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_eddsa_header_with_an_rsa_key_is_refused
    token = Keys.eddsa(Keys.claims, kid: 'rs-1')
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_key_whose_declared_alg_disagrees_is_refused
    jwks = { 'keys' => [Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1', 'alg' => 'PS256')] }
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: jwks), Keys.rs256(Keys.claims)) }
  end

  def test_key_without_alg_is_judged_by_its_type
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1').tap { |k| k.delete('alg') }
    assert_equal 'usr_123', verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.rs256(Keys.claims))['sub']
  end

  def test_ignores_keys_that_carry_private_members
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1', 'd' => 'AQAB')
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.rs256(Keys.claims)) }
  end

  def test_ignores_encryption_keys
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1', 'use' => 'enc')
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.rs256(Keys.claims)) }
  end

  def test_refuses_rsa_keys_under_2048_bits
    jwk = Keys.rsa_jwk(Keys::SMALL_RSA, 'rs-1')
    token = Keys.hand_rs256(Keys.claims, key: Keys::SMALL_RSA)
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), token) }
  end

  def test_a_key_of_another_type_carrying_rsa_parameters_is_refused
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1', 'kty' => 'EC').tap { |k| k.delete('alg') }
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.rs256(Keys.claims)) }
  end

  def test_a_key_of_another_type_carrying_an_ed25519_x_is_refused
    jwk = Keys.ed_jwk(Keys::ED_KEY, 'ed-1', 'kty' => 'RSA')
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.eddsa(Keys.claims)) }
  end

  def test_a_token_without_kid_never_matches_a_key_without_kid
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'x').tap { |k| k.delete('kid') }
    h = Keys.b64({ alg: 'RS256', typ: 'at+jwt' }.to_json)
    p = Keys.b64(Keys.claims.to_json)
    s = Keys.b64(Keys::RSA_KEY.sign(OpenSSL::Digest.new('SHA256'), "#{h}.#{p}"))
    assert_raises(AuthFI::Error) { verify_with(platform(jwks: { 'keys' => [jwk] }), "#{h}.#{p}.#{s}") }
  end

  def test_a_token_over_the_size_cap_is_refused_even_when_validly_signed
    token = Keys.rs256(Keys.claims('pad' => 'x' * (AuthFI::MAX_TOKEN_BYTES + 1)))
    assert_raises(AuthFI::Error) { verify_with(platform, token) }
  end

  def test_signature_in_the_standard_base64_alphabet_is_refused
    token = nil
    loop do
      token = Keys.rs256(Keys.claims)
      break if token.split('.')[2].match?(/[-_]/)
    end
    h, p, s = token.split('.')
    assert_raises(AuthFI::Error) { verify_with(platform, "#{h}.#{p}.#{s.tr('-_', '+/')}") }
  end

  def test_requires_a_kid
    h = Keys.b64({ alg: 'RS256', typ: 'at+jwt' }.to_json)
    p = Keys.b64(Keys.claims.to_json)
    s = Keys.b64(Keys::RSA_KEY.sign(OpenSSL::Digest.new('SHA256'), "#{h}.#{p}"))
    assert_raises(AuthFI::Error) { verify_with(platform, "#{h}.#{p}.#{s}") }
  end

  def test_refuses_unknown_critical_header
    h = Keys.b64({ alg: 'RS256', typ: 'at+jwt', kid: 'rs-1', crit: ['x'], x: 1 }.to_json)
    p = Keys.b64(Keys.claims.to_json)
    s = Keys.b64(Keys::RSA_KEY.sign(OpenSSL::Digest.new('SHA256'), "#{h}.#{p}"))
    assert_raises(AuthFI::Error) { verify_with(platform, "#{h}.#{p}.#{s}") }
  end

  def test_rejects_malformed_tokens
    ['not-a-jwt', 'a.b', 'a.b.c.d', '..', '', 'a..c', nil, 12, "#{'a' * 20_000}.b.c"].each do |bad|
      assert_raises(AuthFI::Error, bad.inspect[0, 20]) { client.verify_token(bad) }
    end
  end
end

class TestAccessTokenType < Minitest::Test
  def test_refuses_an_id_token_offered_as_an_access_token
    id_token = Keys.rs256(Keys.claims('aud' => AUDIENCE, 'nonce' => 'n', 'at_hash' => 'h'), typ: 'JWT')
    err = assert_raises(AuthFI::Error) { verify_with(platform, id_token) }
    assert_equal 'Token is not an access token', err.message
  end

  def test_refuses_a_token_with_no_typ
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims, typ: nil)) }
  end

  def test_refuses_other_typed_tokens
    %w[secevent+jwt txn_token+jwt].each do |typ|
      assert_raises(AuthFI::Error, typ) { verify_with(platform, Keys.eddsa(Keys.claims, typ: typ)) }
    end
  end

  def test_accepts_the_application_form_and_any_case
    ['application/at+jwt', 'AT+JWT', 'Application/At+Jwt'].each do |typ|
      assert_equal 'usr_123', verify_with(platform, Keys.rs256(Keys.claims, typ: typ))['sub'], typ
    end
  end
end

class TestClaims < Minitest::Test
  def test_rejects_wrong_issuer
    err = assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('iss' => 'https://evil.example.com'))) }
    assert_equal 'Invalid token issuer', err.message
  end

  def test_rejects_a_token_with_no_issuer
    c = Keys.claims
    c.delete('iss')
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(c)) }
  end

  def test_rejects_wrong_audience
    err = assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('aud' => ['app_other']))) }
    assert_equal 'Invalid token audience', err.message
  end

  def test_rejects_a_token_with_no_audience
    c = Keys.claims
    c.delete('aud')
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(c)) }
  end

  def test_accepts_aud_as_string_or_array_when_one_matches
    assert verify_with(platform, Keys.rs256(Keys.claims('aud' => AUDIENCE)))
    assert verify_with(platform, Keys.rs256(Keys.claims('aud' => ['x', AUDIENCE])))
  end

  def test_several_configured_audiences
    assert verify_with(platform, Keys.rs256(Keys.claims('aud' => ['app_b'])), audience: [AUDIENCE, 'app_b'])
  end

  def test_refuses_every_token_when_no_audience_is_configured
    err = assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims()), audience: nil) }
    assert_equal 'Token audience not configured', err.message
  end

  def test_audience_that_is_authfis_own_is_a_configuration_error
    [ISSUER, "#{ISSUER}/mcp", "#{ISSUER}/anything", 'https://ACME.authfi.io/mcp', 'https://acme.authfi.io:443/mcp',
     'HTTPS://acme.authfi.io', 'https://acme.authfi.io./mcp'].each do |a|
      assert_raises(ArgumentError, a) { client(audience: a) }
    end
  end

  def test_rejects_expired_token
    err = assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('exp' => Time.now.to_i - 3600))) }
    assert_equal 'Token expired', err.message
  end

  def test_rejects_a_token_with_no_expiry
    c = Keys.claims
    c.delete('exp')
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(c)) }
  end

  def test_rejects_a_token_whose_expiry_is_not_a_number
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.hand_rs256(Keys.claims('exp' => 'never'), key: Keys::RSA_KEY)) }
  end

  def test_leeway_tolerates_small_clock_skew_only
    assert verify_with(platform, Keys.rs256(Keys.claims('exp' => Time.now.to_i - 10)))
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('exp' => Time.now.to_i - 120))) }
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('exp' => Time.now.to_i - 10)), leeway: 0) }
  end

  def test_rejects_not_yet_valid_and_future_issued
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('nbf' => Time.now.to_i + 600))) }
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(Keys.claims('iat' => Time.now.to_i + 600))) }
  end

  def test_rejects_a_token_with_no_subject
    c = Keys.claims
    c.delete('sub')
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.rs256(c)) }
  end

  def test_jwks_failure_never_passes_a_token
    auth = client
    boom = ->(*) { raise AuthFI::Error.new('Fetch failed: boom') }
    err = assert_raises(AuthFI::Error) { auth.stub(:http_get, boom) { auth.verify_token(Keys.rs256(Keys.claims)) } }
    assert_equal 401, err.status
  end
end

class TestNoSecretInOutput < Minitest::Test
  SECRET = 'sk_live_SECRET_VALUE_123'.freeze

  def test_inspect_to_s_and_pp_hide_the_api_key
    auth = AuthFI.new(tenant: 'acme', api_key: SECRET, audience: AUDIENCE)
    io = StringIO.new
    PP.pp(auth, io)
    [auth.inspect, auth.to_s, "#{auth}", io.string].each { |s| refute_includes s, SECRET }
  end

  def test_cannot_be_dumped_to_yaml
    auth = AuthFI.new(tenant: 'acme', api_key: SECRET, audience: AUDIENCE)
    assert_raises(TypeError) { YAML.dump(auth) }
    refute_includes auth.instance_variables.map { |v| auth.instance_variable_get(v).inspect }.join, SECRET
  end

  def test_cannot_be_marshalled
    assert_raises(TypeError) { Marshal.dump(AuthFI.new(tenant: 'acme', api_key: SECRET)) }
  end

  def test_refusals_never_echo_the_token
    token = Keys.rs256(Keys.claims('aud' => ['app_other']))
    auth = client
    err = auth.stub(:http_get, ->(u) { platform.call(u) }) do
      assert_raises(AuthFI::Error) { auth.verify_token(token) }
    end
    refute_includes err.message, token
    refute_includes err.message, token.split('.')[1]
  end

  def test_malformed_input_is_not_echoed
    bad = 'eyJhbGciOiJSUzI1NiJ9.SECRET-PAYLOAD.c2ln'
    err = assert_raises(AuthFI::Error) { client.verify_token(bad) }
    refute_includes err.message, 'SECRET-PAYLOAD'
  end

  def test_sync_failure_does_not_print_the_response_body
    auth = AuthFI.new(tenant: 'acme', api_key: SECRET)
    auth.register_permission('read:users')
    fake = Struct.new(:code, :body).new('500', "echo #{SECRET}")
    http = Object.new
    sent = nil
    http.define_singleton_method(:request) { |req| sent = req; fake }
    _, err = capture_io do
      Net::HTTP.stub(:start, ->(*_a, **_k, &blk) { blk.call(http) }) { auth.sync! }
    end
    refute_includes err, SECRET
    assert_includes err, 'HTTP 500'
    assert_equal SECRET, sent['X-API-Key'], 'the key still reaches the sync request'
  end

  def test_sync_requires_an_api_key
    auth = AuthFI.new(tenant: 'acme')
    auth.register_permission('read:users')
    assert_raises(AuthFI::Error) { auth.sync! }
  end
end

class TestAuthenticate < Minitest::Test
  Req = Struct.new(:headers)

  def test_reads_the_bearer_token
    auth = client
    token = Keys.rs256(Keys.claims)
    claims = auth.stub(:http_get, ->(u) { platform.call(u) }) { auth.authenticate(Req.new({ 'Authorization' => "Bearer #{token}" })) }
    assert_equal 'usr_123', claims['sub']
  end

  def test_missing_header_is_refused
    assert_raises(AuthFI::Error) { client.authenticate(Req.new({})) }
  end
end

class TestRequirePermissions < Minitest::Test
  def test_passes_with_matching_permissions
    assert_nil client.require_permissions!({ 'permissions' => %w[read:users write:users] }, 'read:users')
  end

  def test_raises_on_missing_permission
    err = assert_raises(AuthFI::Error) { client.require_permissions!({ 'permissions' => ['read:users'] }, 'delete:users') }
    assert_equal 403, err.status
    assert_includes err.message, 'delete:users'
  end

  def test_handles_empty_permissions
    assert_raises(AuthFI::Error) { client.require_permissions!({}, 'read:users') }
  end
end

class TestRequireRole < Minitest::Test
  def test_passes_with_matching_role
    assert_nil client.require_role!({ 'roles' => ['editor'] }, 'admin', 'editor')
  end

  def test_raises_on_missing_role
    err = assert_raises(AuthFI::Error) { client.require_role!({ 'roles' => ['viewer'] }, 'admin') }
    assert_equal 403, err.status
  end

  def test_handles_empty_roles
    assert_raises(AuthFI::Error) { client.require_role!({}, 'admin') }
  end
end

class TestMisc < Minitest::Test
  def test_the_gemspec_loads_files_from_the_gem_root
    spec = Gem::Specification.load(File.join(__dir__, 'authfi.gemspec'))
    assert_equal ['.'], spec.require_paths
    assert_includes spec.files, 'authfi.rb'
  end

  def test_sync_empty_is_noop
    assert_nil client(api_key: 'k').sync!
  end

  def test_error_status
    assert_equal 401, AuthFI::Error.new('t').status
    assert_equal 403, AuthFI::Error.new('t', status: 403).status
  end
end

# ---- review r1 additions (append to test_authfi.rb) ----
class TestReviewR1 < Minitest::Test
  def refused(&blk)
    err = assert_raises(AuthFI::Error, &blk)
    assert_equal 401, err.status
    err
  end

  def now
    Time.now.to_i
  end

  def test_a_fourth_segment_is_refused
    refused { verify_with(platform, Keys.rs256(Keys.claims) + '.AAAA') }
  end

  def test_a_trailing_dot_is_refused
    refused { verify_with(platform, Keys.rs256(Keys.claims) + '.') }
  end

  def test_iss_that_merely_starts_with_the_issuer_is_refused
    refused { verify_with(platform, Keys.rs256(Keys.claims('iss' => "#{ISSUER}/x"))) }
  end

  def test_empty_and_non_string_sub_are_refused
    refused { verify_with(platform, Keys.rs256(Keys.claims('sub' => ''))) }
    refused { verify_with(platform, Keys.rs256(Keys.claims('sub' => 123))) }
  end

  def test_nbf_and_iat_inside_the_leeway_are_accepted
    assert verify_with(platform, Keys.rs256(Keys.claims('nbf' => now + 30)))
    assert verify_with(platform, Keys.rs256(Keys.claims('iat' => now + 30)))
  end

  def test_exp_and_nbf_boundaries_with_a_frozen_clock
    t = now
    expired = Keys.rs256(Keys.claims('exp' => t - 60))
    barely = Keys.rs256(Keys.claims('exp' => t - 59, 'nbf' => t + 60))
    Time.stub(:now, Time.at(t)) do
      refused { verify_with(platform, expired) }
      assert verify_with(platform, barely)
    end
  end

  def test_a_key_with_a_private_member_k_is_refused
    refused { verify_with(platform(jwks: { 'keys' => [Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1', 'k' => 'AAAA')] }), Keys.rs256(Keys.claims)) }
  end

  def test_a_key_without_use_is_accepted
    jwk = Keys.rsa_jwk(Keys::RSA_KEY, 'rs-1')
    jwk.delete('use')
    assert verify_with(platform(jwks: { 'keys' => [jwk] }), Keys.rs256(Keys.claims))
  end

  def test_kid_must_match_exactly_not_by_prefix
    refused { verify_with(platform, Keys.rs256(Keys.claims, kid: 'rs')) }
  end

  def test_an_okp_key_of_another_curve_is_refused
    jwks = { 'keys' => [Keys.ed_jwk(Keys::ED_KEY, 'ed-1', 'crv' => 'X25519')] }
    refused { verify_with(platform(jwks: jwks), Keys.eddsa(Keys.claims)) }
  end

  def test_the_cache_expires_after_jwks_ttl_and_rediscovers
    web = platform
    auth = client
    t = Keys.rs256(Keys.claims)
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      auth.verify_token(t)
      Time.stub(:now, Time.at(now + 301)) { auth.verify_token(t) }
    end
    assert_equal 4, web.calls.size
  end

  def test_an_unknown_kid_refetches_the_jwks_but_not_discovery
    web = platform
    auth = client
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      auth.verify_token(Keys.rs256(Keys.claims))
      Time.stub(:now, Time.at(now + 31)) { refused { auth.verify_token(Keys.rs256(Keys.claims, kid: 'nope')) } }
    end
    assert_equal ["#{ISSUER}/.well-known/openid-configuration", JWKS_URI, JWKS_URI], web.calls
  end

  def test_a_malformed_jwks_is_not_cached
    good = false
    web = FakeWeb.new("#{ISSUER}/.well-known/openid-configuration" => discovery,
                      JWKS_URI => -> { good ? Keys.jwks : { 'nokeys' => 1 } })
    auth = client
    t = Keys.rs256(Keys.claims)
    auth.stub(:http_get, ->(u) { web.call(u) }) do
      refused { auth.verify_token(t) }
      good = true
      assert auth.verify_token(t)
    end
  end

  def test_a_non_200_answer_is_never_used_even_with_a_valid_body
    auth = client
    web = platform
    stub = ->(u) { u.include?("/.well-known/") ? [302, discovery.to_json] : web.call(u) }
    auth.stub(:http_get, stub) { refused { auth.verify_token(Keys.rs256(Keys.claims)) } }
  end

  def test_an_empty_or_non_string_kid_never_matches_a_key
    jwks = { "keys" => [Keys.rsa_jwk(Keys::RSA_KEY, "")] }
    refused { verify_with(platform(jwks: jwks), Keys.rs256(Keys.claims, kid: "")) }
    jwks = { "keys" => [Keys.rsa_jwk(Keys::RSA_KEY, 1)] }
    refused { verify_with(platform(jwks: jwks), Keys.rs256(Keys.claims, kid: 1)) }
  end

  def test_real_http_accepts_a_document_of_exactly_the_size_limit_and_sends_its_headers
    seen = {}
    srv = TCPServer.new('127.0.0.1', 0)
    port = srv.addr[1]
    base = "http://127.0.0.1:#{port}"
    Thread.new do
      loop do
        s = srv.accept
        path = s.gets.to_s.split(' ')[1]
        while (l = s.gets) && l != "\r\n"
          seen[l.split(':', 2)[0].downcase] = l.split(':', 2)[1].to_s.strip
        end
        doc = path == '/jwks' ? Keys.jwks : { 'issuer' => base, 'jwks_uri' => "#{base}/jwks" }
        json = doc.to_json
        body = json.chomp('}') + ',"pad":"' + ('x' * (AuthFI::MAX_DOC_BYTES - json.bytesize - 9)) + '"}'
        s.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        s.close
      rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::EPIPE
        break
      end
    end
    assert client(issuer: base).verify_token(Keys.rs256(Keys.claims('iss' => base)))
    assert_equal 'application/json', seen['accept']
    assert_match(/authfi-ruby/, seen['user-agent'])
  ensure
    srv&.close
  end

  def test_a_transport_failure_message_does_not_carry_the_url
    err = assert_raises(AuthFI::Error) { client.send(:http_get, 'http://127.0.0.1:1/secret-path') }
    refute_match(/127\.0\.0\.1|secret-path/, err.message)
  end

  def test_https_issuer_is_fetched_over_tls
    srv = TCPServer.new("127.0.0.1", 0)
    first = nil
    t = Thread.new { s = srv.accept; first = s.readpartial(1); s.close }
    auth = client(jwks_ttl: 1)
    auth.stub(:jwks_uri, ->(_n) { "https://127.0.0.1:#{srv.addr[1]}/jwks" }) do
      assert_raises(AuthFI::Error) { auth.send(:fetch_jwks) }
    end
    t.join(5)
    assert_equal "".b, first.to_s.b
  ensure
    srv&.close
  end

  def test_issuer_with_userinfo_or_fragment_is_a_configuration_error
    assert_raises(ArgumentError) { client(issuer: 'https://u@acme.authfi.io') }
    assert_raises(ArgumentError) { client(issuer: 'https://acme.authfi.io#f') }
  end

  def test_an_empty_string_audience_accepts_nothing
    refused { verify_with(platform, Keys.rs256(Keys.claims('aud' => [''])), audience: '') }
  end

  def test_a_header_or_payload_that_is_not_an_object_is_refused_with_authfi_error
    ['[]', '"x"', '1', 'null'].each do |raw|
      refused { verify_with(platform, "#{Keys.b64(raw)}.#{Keys.b64('{}')}.#{Keys.b64('s')}") }
      h = Keys.b64({ alg: 'RS256', typ: 'at+jwt', kid: 'rs-1' }.to_json)
      refused { verify_with(platform, "#{h}.#{Keys.b64(raw)}.#{Keys.b64('s')}") }
    end
  end

  def test_a_valid_token_of_exactly_the_size_limit_is_accepted
    token = nil
    (11_000..12_400).each do |pad|
      t = Keys.hand_rs256(Keys.claims("pad" => "x" * pad), key: Keys::RSA_KEY)
      (token = t; break) if t.bytesize == AuthFI::MAX_TOKEN_BYTES
    end
    skip 'size not reachable' unless token
    assert verify_with(platform, token)
    refused { verify_with(platform, token + 'A') }
  end

  def test_concurrent_first_requests_fetch_the_jwks_once
    web = platform
    auth = client
    auth.define_singleton_method(:http_get) { |u| sleep 0.05; web.call(u) }
    t = Keys.rs256(Keys.claims)
    8.times.map { Thread.new { auth.verify_token(t) } }.each(&:join)
    assert_equal 2, web.calls.size
  end

  def test_real_http_does_not_follow_a_redirect_to_a_valid_document
    srv = TCPServer.new('127.0.0.1', 0)
    port = srv.addr[1]
    base = "http://127.0.0.1:#{port}"
    Thread.new do
      loop do
        s = srv.accept
        path = s.gets.to_s.split(' ')[1]
        while (l = s.gets) && l != "\r\n"; end
        status, extra, body =
          case path
          when '/.well-known/openid-configuration' then [302, "Location: #{base}/elsewhere\r\n", '']
          when '/elsewhere' then [200, '', { 'issuer' => base, 'jwks_uri' => "#{base}/jwks" }.to_json]
          when '/jwks' then [200, '', Keys.jwks.to_json]
          else [404, '', '']
          end
        s.write("HTTP/1.1 #{status} X\r\n#{extra}Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
        s.close
      rescue IOError, Errno::EBADF, Errno::ECONNRESET, Errno::EPIPE
        break
      end
    end
    refused { client(issuer: base).verify_token(Keys.rs256(Keys.claims('iss' => base))) }
  ensure
    srv&.close
  end
end

# Bugs found by the review; these FAIL on the current code and pass once fixed.
class TestReviewR1Bugs < Minitest::Test
  def test_invalid_utf8_in_the_header_is_an_auth_error_not_an_argument_error
    h = Keys.b64("{\"alg\":\"RS256\",\"typ\":\"\xff\",\"kid\":\"rs-1\"}".b)
    t = "#{h}.#{Keys.b64('{}')}.#{Keys.b64('s')}"
    assert_raises(AuthFI::Error) { verify_with(platform, t) }
  end

  def test_a_null_nbf_or_iat_is_refused
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.hand_rs256(Keys.claims('nbf' => nil), key: Keys::RSA_KEY)) }
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.hand_rs256(Keys.claims('iat' => nil), key: Keys::RSA_KEY)) }
  end

  def test_a_non_numeric_nbf_or_iat_is_refused
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.hand_rs256(Keys.claims('nbf' => '9999999999'), key: Keys::RSA_KEY)) }
    assert_raises(AuthFI::Error) { verify_with(platform, Keys.hand_rs256(Keys.claims('iat' => '9999999999'), key: Keys::RSA_KEY)) }
  end
end
