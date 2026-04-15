class Rack::Attack 
  Rack::Attack.cache.store = ActiveSupport::Cache::RedisCacheStore.new(
    url: ENV.fetch("REDIS_URL", "redis://localhost:6379/0")
  )

  def self.limit(env_key, default)
    ENV.fetch(env_key, default).to_i
  end

  safelist("allow-localhost") do |req|
    req.ip == "127.0.0.1" || req.ip == "::1" if Rails.env.development?
  end

  throttle(
    "login/ip",
    limit: limit("RATE_LIMIT_LOGIN_MAX", 5),
    period: limit("RATE_LIMIT_LOGIN_PERIOD", 300)
  ) do |req|
    req.ip if req.path == "/api/v1/signin" && req.post?
  end

  throttle(
    "login/email",
    limit: limit("RATE_LIMIT_LOGIN_MAX", 5),
    period: limit("RATE_LIMIT_LOGIN_PERIOD", 300)
  ) do |req|
    if req.path == "/api/v1/signin" && req.post?
      body = parse_body(req)
      email = body.dig("user", "email").to_s.downcase.presence
      email
    end
  end

  throttle(
    "signup/ip",
    limit: limit("RATE_LIMIT_SIGNUP_MAX", 3),
    period: limit("RATE_LIMIT_SIGNUP_PERIOD", 3600)
  ) do |req|
    req.ip if req.path == "/api/v1/signup" && req.post?
  end

  throttle(
    "refresh/ip",
    limit: limit("RATE_LIMIT_REFRESH_MAX", 10),
    period: limit("RATE_LIMIT_REFRESH_PERIOD", 300)
  ) do |req|
    req.ip if req.path == "/api/v1/refresh" && req.post?
  end

  throttle(
    "global/ip",
    limit: limit("RATE_LIMIT_GLOBAL_MAX", 300),
    period: limit("RATE_LIMIT_GLOBAL_PERIOD", 60)
  ) do |req|
    req.ip unless req.path.start_with?("/assets")
  end

  blocklist("block-brute-force-ip") do |req|
    Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 20, findtime: 1.hour, bantime: 1.hour) do
      (req.path == "/api/v1/signin" || req.path == "/api/v1/signup") && req.post?
    end
  end

  self.throttled_responder = lambda do |req|
    match_data = req.env["rack.attack.match_data"]
    now        = match_data[:epoch_time]
    period     = match_data[:period]
    retry_after = period - (now % period)

    [
      429,
      {
        "Content-Type"  => "application/json",
        "Retry-After"   => retry_after.to_s,
        "X-RateLimit-Limit"     => match_data[:limit].to_s,
        "X-RateLimit-Remaining" => "0",
        "X-RateLimit-Reset"     => (now + retry_after).to_s
      },
      [{ message: "Too many requests. Please try again later.", retry_after: retry_after }.to_json]
    ]
  end

  self.blocklisted_responder = lambda do |_req|
    [
      403,
      { "Content-Type" => "application/json" },
      [{ message: "Your IP has been temporarily blocked due to suspicious activity." }.to_json]
    ]
  end

  def self.parse_body(req)
    body = req.body.read
    req.body.rewind
    JSON.parse(body)
  rescue JSON::ParseError
    {}
  end
end