# AuthFI Ruby SDK
#
# Usage (Rails):
#   AUTH = AuthFI.new(
#     tenant: 'acme',
#     issuer: 'https://acme.authfi.io',      # your project's issuer
#     audience: 'app_xxxxxxxx',              # the client id(s) your API accepts
#     api_key: 'sk_live_...'                 # only needed for sync!
#   )
#
#   class ApplicationController < ActionController::API
#     before_action :authenticate!
#
#     def authenticate!
#       @current_user = AUTH.authenticate(request)
#     end
#
#     def require_permission!(*perms)
#       AUTH.require_permissions!(@current_user, *perms)
#     end
#   end
#
#   # On startup (config/initializers/authfi.rb)
#   AUTH.sync!

require 'net/http'
require 'json'
require 'openssl'
require 'timeout'
require 'uri'

class AuthFI
  class Error < StandardError
    attr_reader :status
    def initialize(message, status: 401)
      super(message)
      @status = status
    end
  end

  # The only signing algorithms a token may use. People and machine clients
  # are signed RS256; AI agents are signed EdDSA (Ed25519).
  ALLOWED_ALGS = %w[RS256 EdDSA].freeze

  # An access token's `typ` header (RFC 9068). An ID token carries `JWT`, so
  # it can never be presented as an access token.
  ACCESS_TOKEN_TYPES = %w[at+jwt application/at+jwt].freeze

  VERSION = '0.2.0'.freeze
  # The edge refuses requests that carry no recognisable User-Agent.
  USER_AGENT = "authfi-ruby/#{VERSION} (ruby #{RUBY_VERSION})".freeze

  MAX_TOKEN_BYTES = 16 * 1024
  MAX_DOC_BYTES = 256 * 1024
  # An unknown `kid` triggers at most one JWKS refetch per this many seconds,
  # so a stream of invented kids cannot turn every request into a fetch.
  JWKS_MIN_REFETCH_SECONDS = 30
  PRIVATE_JWK_MEMBERS = %w[d p q dp dq qi k].freeze
  # DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow.
  ED25519_SPKI_PREFIX = ["302a300506032b6570032100"].pack('H*').freeze

  # tenant:   the project slug.
  # issuer:   the project's issuer URL. Defaults to https://<tenant>.authfi.io;
  #           pass it explicitly for a custom domain. Discovery, the JWKS and
  #           the expected `iss` all come from it.
  # audience: the `aud` value(s) your API accepts. Required to verify tokens:
  #           with none configured every token is refused.
  # api_key:  only needed for sync!.
  # jwks_ttl: how long (seconds) to trust cached discovery/JWKS before refetching.
  # leeway:   clock-skew tolerance (seconds) for exp/nbf/iat.
  # fetch_timeout: total seconds one discovery or JWKS fetch may take, headers and body included.
  def initialize(tenant:, api_key: nil, api_url: 'https://api.authfi.io',
                 application_id: nil, jwks_ttl: 300, issuer: nil, audience: nil,
                 leeway: 60, fetch_timeout: 30)
    @tenant = tenant
    key = api_key
    # Held in a lambda: YAML.dump and as_json then cannot read it from an instance variable.
    @api_key = key.nil? ? nil : -> { key }
    @api_url = api_url
    @application_id = application_id
    @jwks_ttl = jwks_ttl
    @leeway = leeway
    @fetch_timeout = fetch_timeout
    @issuer = validate_issuer(issuer || "https://#{tenant}.authfi.io")
    @audiences = validate_audiences(audience)
    @registered_permissions = {}

    @jwks = nil
    @jwks_fetched_at = 0
    @jwks_uri = nil
    @jwks_uri_fetched_at = 0
    @mutex = Mutex.new
  end

  # A configuration object never prints its secret.
  def inspect
    "#<AuthFI tenant=#{@tenant.inspect} issuer=#{@issuer.inspect}>"
  end
  alias to_s inspect

  def encode_with(_coder)
    raise TypeError, 'AuthFI holds credentials and cannot be dumped'
  end

  def marshal_dump
    raise TypeError, 'AuthFI holds credentials and cannot be marshalled'
  end

  # Authenticate request, return decoded claims
  def authenticate(request)
    auth = request.headers['Authorization'] || ''
    raise Error.new('Missing authorization') unless auth.start_with?('Bearer ')
    verify_token(auth[7..])
  end

  # Verify an access token and return its claims (string keys).
  #
  # Requires: a compact JWS of three parts; alg RS256 or EdDSA, matching the
  # issuer's published key for the token's kid; typ at+jwt; a valid signature;
  # iss equal to the configured issuer; aud containing a configured audience;
  # exp present and not past; sub present. Any failure raises AuthFI::Error
  # (status 401) with a fixed message that never contains the token.
  def verify_token(token)
    raise Error.new('Invalid token') unless token.is_a?(String)
    raise Error.new('Invalid token') if token.bytesize > MAX_TOKEN_BYTES
    parts = token.split('.', -1)
    raise Error.new('Invalid token') unless parts.length == 3 && parts.none?(&:empty?)

    header = decode_segment(parts[0])
    payload = decode_segment(parts[1])
    signature = decode_b64url(parts[2])

    alg = header['alg']
    raise Error.new('Unsupported token algorithm') unless ALLOWED_ALGS.include?(alg)
    unless header['typ'].is_a?(String) && ACCESS_TOKEN_TYPES.include?(header['typ'].downcase)
      raise Error.new('Token is not an access token')
    end
    kid = header['kid']
    raise Error.new('Invalid token header') unless kid.is_a?(String) && !kid.empty?
    raise Error.new('Unsupported token header') if header.key?('crit')

    key = signing_key(kid, alg)
    unless signature_valid?(alg, key, "#{parts[0]}.#{parts[1]}", signature)
      raise Error.new('Invalid token signature')
    end

    validate_claims(payload)
    payload
  rescue ArgumentError, EncodingError, TypeError, JSON::JSONError
    # Malformed input must read as a refusal, never as a crash (an invalid UTF-8
    # header value raises ArgumentError in String#downcase, for example).
    raise Error.new('Invalid token')
  end

  # Check ALL permissions (raises on failure)
  def require_permissions!(claims, *permissions)
    user_perms = claims['permissions'] || []
    permissions.each { |p| register_permission(p) }

    missing = permissions - user_perms
    unless missing.empty?
      raise Error.new("Missing permissions: #{missing.join(', ')}", status: 403)
    end
  end

  # Check ANY role (raises on failure)
  def require_role!(claims, *roles)
    user_roles = claims['roles'] || []
    unless roles.any? { |r| user_roles.include?(r) }
      raise Error.new('Insufficient role', status: 403)
    end
  end

  def register_permission(name, description = nil)
    @registered_permissions[name] ||= description
  end

  # Sync permissions to AuthFI
  def sync!
    return if @registered_permissions.empty?
    api_key = @api_key&.call.to_s
    raise Error.new('api_key is required to sync permissions', status: 500) if api_key.empty?

    body = {
      permissions: @registered_permissions.map { |name, desc|
        h = { name: name }
        h[:description] = desc if desc
        h
      }
    }
    body[:application_id] = @application_id if @application_id

    # The edge dispatch is api.authfi.io/<slug>/<path> — slug FIRST — and no /manage/ prefix
    # exists on the platform; those routes are /v1/* like the rest.
    uri = URI("#{@api_url}/#{@tenant}/v1/permissions/sync")
    req = Net::HTTP::Put.new(uri)
    req['X-API-Key'] = api_key
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }

    if res.code.to_i < 400
      data = JSON.parse(res.body)
      puts "[authfi] Synced #{data['synced']} permissions (#{data['total']} total)"
    else
      warn "[authfi] Sync failed: HTTP #{res.code}"
    end
  end

  private

  def loopback?(host)
    %w[localhost 127.0.0.1 ::1 [::1]].include?(host)
  end

  def validate_issuer(value)
    uri = URI.parse(value.to_s)
    ok = uri.is_a?(URI::HTTP) && uri.host && !uri.host.empty? &&
         uri.query.nil? && uri.fragment.nil? && uri.userinfo.nil? &&
         (uri.path.nil? || uri.path.empty?) && !value.to_s.end_with?('/') &&
         (uri.scheme == 'https' || loopback?(uri.host))
    raise ArgumentError, 'issuer must be an https URL (http only for localhost) with no path, query or trailing slash' unless ok
    value.to_s
  rescue URI::InvalidURIError
    raise ArgumentError, 'issuer is not a valid URL'
  end

  # AuthFI's own audiences name the gateway, not your API. Accepting one would
  # let a token minted for the gateway be replayed at your API.
  def validate_audiences(value)
    list = Array(value).map(&:to_s).reject(&:empty?)
    list.each do |a|
      if own_audience?(a)
        raise ArgumentError, "audience #{a} is AuthFI's own; use your API's client id"
      end
    end
    list.freeze
  end

  # An audience is AuthFI's own when it is the issuer or a URL under it, compared
  # after the scheme and host are lower-cased and a default port is dropped.
  def own_audience?(audience)
    issuer = normalize_url(@issuer)
    candidate = normalize_url(audience)
    candidate == issuer || candidate.start_with?("#{issuer}/")
  end

  def normalize_url(value)
    u = URI.parse(value)
    return value unless u.is_a?(URI::HTTP) && u.host
    port = u.port == u.default_port ? '' : ":#{u.port}"
    "#{u.scheme.downcase}://#{u.host.downcase.chomp('.')}#{port}#{u.path}"
  rescue URI::InvalidURIError
    value
  end

  def decode_b64url(segment)
    raise Error.new('Invalid token') unless segment.match?(/\A[A-Za-z0-9_-]+\z/)
    (segment.tr('-_', '+/') + '=' * ((4 - segment.length % 4) % 4)).unpack1('m0')
  rescue ArgumentError
    raise Error.new('Invalid token')
  end

  def decode_segment(segment)
    obj = JSON.parse(decode_b64url(segment))
    raise Error.new('Invalid token') unless obj.is_a?(Hash)
    obj
  rescue JSON::ParserError
    raise Error.new('Invalid token')
  end

  # Verify `signing_input` against `signature` with the public key.
  def signature_valid?(alg, key, signing_input, signature)
    case alg
    when 'RS256' then key.verify(OpenSSL::Digest.new('SHA256'), signature, signing_input)
    when 'EdDSA' then key.verify(nil, signature, signing_input)
    else false
    end
  rescue OpenSSL::PKey::PKeyError
    false
  end

  def validate_claims(claims)
    raise Error.new('Invalid token issuer') unless claims['iss'] == @issuer

    raise Error.new('Token audience not configured') if @audiences.empty?
    aud = claims['aud']
    aud = [aud] if aud.is_a?(String)
    unless aud.is_a?(Array) && aud.any? { |a| @audiences.include?(a) }
      raise Error.new('Invalid token audience')
    end

    now = Time.now.to_i
    exp = claims['exp']
    raise Error.new('Invalid token expiry') unless exp.is_a?(Numeric)
    raise Error.new('Token expired') if exp <= now - @leeway

    if claims.key?('nbf')
      nbf = claims['nbf']
      raise Error.new('Invalid token not-before') unless nbf.is_a?(Numeric)
      raise Error.new('Token not yet valid') if nbf > now + @leeway
    end
    if claims.key?('iat')
      iat = claims['iat']
      raise Error.new('Invalid token issued-at') unless iat.is_a?(Numeric) && iat <= now + @leeway
    end

    sub = claims['sub']
    raise Error.new('Invalid token subject') unless sub.is_a?(String) && !sub.empty?
  end

  # The key published for `kid`, as an OpenSSL public key, for the token's alg.
  def signing_key(kid, alg)
    jwk = find_jwk(fetch_jwks, kid)
    jwk ||= find_jwk(fetch_jwks(force: true), kid)
    raise Error.new('Unknown signing key') unless jwk
    key_from_jwk(jwk, alg) || raise(Error.new('Signing key does not match token algorithm'))
  end

  def find_jwk(doc, kid)
    keys = doc.is_a?(Hash) ? doc['keys'] : nil
    return nil unless keys.is_a?(Array)
    keys.find do |k|
      k.is_a?(Hash) && k['kid'] == kid &&
        (k['use'].nil? || k['use'] == 'sig') &&
        PRIVATE_JWK_MEMBERS.none? { |m| k.key?(m) }
    end
  end

  # Builds the public key, requiring the JWK's key type (and `alg`, when it
  # states one) to agree with the token's alg. Returns nil on a mismatch.
  def key_from_jwk(jwk, alg)
    declared = jwk['alg']
    return nil if declared && declared != alg
    case alg
    when 'RS256'
      return nil unless jwk['kty'] == 'RSA'
      n = OpenSSL::BN.new(decode_b64url(jwk['n'].to_s), 2)
      e = OpenSSL::BN.new(decode_b64url(jwk['e'].to_s), 2)
      return nil if n.num_bits < 2048
      der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der
      OpenSSL::PKey::RSA.new(der)
    when 'EdDSA'
      return nil unless jwk['kty'] == 'OKP' && jwk['crv'] == 'Ed25519'
      raw = decode_b64url(jwk['x'].to_s)
      return nil unless raw.bytesize == 32
      OpenSSL::PKey.read(ED25519_SPKI_PREFIX + raw)
    end
  rescue OpenSSL::OpenSSLError, ArgumentError
    nil
  end

  # Fetch + cache the issuer's JWKS, at the jwks_uri its discovery document
  # names. Cached for @jwks_ttl seconds. `force: true` (an unknown kid) bypasses
  # the cache but only once per JWKS_MIN_REFETCH_SECONDS. A failure is never
  # cached.
  def fetch_jwks(force: false)
    @mutex.synchronize do
      now = Time.now.to_i
      age = now - @jwks_fetched_at
      fresh = @jwks && age < @jwks_ttl
      return @jwks if fresh && !force
      return @jwks if @jwks && force && age < JWKS_MIN_REFETCH_SECONDS

      doc = fetch_json(jwks_uri(now))
      unless doc.is_a?(Hash) && doc['keys'].is_a?(Array)
        raise Error.new('JWKS fetch failed: unexpected document')
      end
      @jwks = doc
      @jwks_fetched_at = now
      @jwks
    end
  end

  # The jwks_uri from <issuer>/.well-known/openid-configuration, falling back to
  # oauth-authorization-server. The document's issuer must equal ours.
  def jwks_uri(now)
    return @jwks_uri if @jwks_uri && (now - @jwks_uri_fetched_at) < @jwks_ttl

    doc = nil
    %w[openid-configuration oauth-authorization-server].each do |name|
      begin
        candidate = fetch_json("#{@issuer}/.well-known/#{name}")
        if candidate.is_a?(Hash)
          doc = candidate
          break
        end
      rescue Error
        next
      end
    end
    raise Error.new('Discovery failed') unless doc.is_a?(Hash)
    raise Error.new('Discovery issuer mismatch') unless doc['issuer'] == @issuer
    uri = doc['jwks_uri']
    begin
      parsed = URI.parse(uri.to_s)
    rescue URI::InvalidURIError
      raise Error.new('Discovery document has no valid jwks_uri')
    end
    # Plain http is allowed only for a loopback jwks_uri of a loopback http issuer, so a
    # remote issuer cannot point the SDK at a service on this host.
    local_http = parsed.scheme == 'http' && loopback?(parsed.host.to_s) && @issuer.start_with?('http://')
    unless parsed.is_a?(URI::HTTP) && parsed.host && (parsed.scheme == 'https' || local_http)
      raise Error.new('Discovery document has no valid jwks_uri')
    end
    @jwks_uri = uri
    @jwks_uri_fetched_at = now
    uri
  end

  def fetch_json(url)
    code, body = http_get(url)
    raise Error.new("Fetch failed: HTTP #{code}") unless code == 200
    JSON.parse(body)
  rescue JSON::ParserError, EncodingError
    raise Error.new('Fetch failed: not JSON')
  end

  # One GET: no redirects followed, no content decoding, and bounded time and size
  # (the body is read in chunks and the read stops at the cap). Returns [code, body].
  def http_get(url)
    uri = URI(url)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.open_timeout = 5
    http.read_timeout = 10
    # Naming an encoding stops Net::HTTP from inflating the answer, so a small
    # gzip body cannot expand past the size cap.
    request = Net::HTTP::Get.new(uri, 'Accept' => 'application/json', 'User-Agent' => USER_AGENT,
                                      'Accept-Encoding' => 'identity')
    code = nil
    body = +''
    # One deadline over the whole exchange: the per-read timeout alone lets a peer that
    # drips a byte at a time hold the call open.
    Timeout.timeout(@fetch_timeout, Error, 'Fetch failed: timed out') do
      http.start do |conn|
        conn.request(request) do |res|
          code = res.code.to_i
          res.read_body do |chunk|
            body << chunk
            raise Error.new('Fetch failed: response too large') if body.bytesize > MAX_DOC_BYTES
          end
        end
      end
    end
    [code, body]
  rescue Error
    raise
  rescue StandardError => e
    raise Error.new("Fetch failed: #{e.class}")
  end
end
