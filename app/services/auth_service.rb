class AuthService
  ALGORITHM = ENV.fetch("JWT_ALGORITHM")

  JWT_ACCESS_TOKEN = ENV.fetch("JWT_ACCESS_TOKEN")
  JWT_REFRESH_TOKEN = ENV.fetch("JWT_REFRESH_TOKEN")

  ACCESS_TOKEN_EXPIRY = 15.minutes.to_i
  REFRESH_TOKEN_EXPIRY = 7.days.to_i

def self.generate_token_pair(user_id)
    {
      access_token:  build_token(user_id, ACCESS_TOKEN_EXPIRY,  "access",  ACCESS_TOKEN_SECRET),
      refresh_token: build_token(user_id, REFRESH_TOKEN_EXPIRY, "refresh", REFRESH_TOKEN_SECRET)
    }
  end


  def self.encode_access_token(user_id)
    build_token(user_id, ACCESS_TOKEN_EXPIRY, "access", JWT_ACCESS_TOKEN)
  end

  def self.encode_refresh_token(user_id)
    build_token(user_id, REFRESH_TOKEN_EXPIRY, "refresh", JWT_REFRESH_TOKEN)
  end

  def self.decode_access_token(token)
    decode(token, JWT_ACCESS_TOKEN, expected_type: "access")
  end

  def self.decode_refresh_token(token)
    decode(token, JWT_REFRESH_TOKEN, expected_type: "refresh")
  end

  private 

  def self.build_token(user_id, expiration, type, secret)
    payload = {
      user_id: user_id,
      type: type,
      jti: SecureRandom.uuid,
      iat: Time.current.to_i,
      exp: expiration
    }

    {
      token:  encode(payload, secret),
      exp_at: expiration
    }
  end

  def self.decode(raw_token, secret, expected_type: nil)
    raise JwtError, "Missing token" if raw_token.blank?

    payload, = JWT.decode(raw_token, secret, true, { algorithm: ALGORITHM })

    if expected_type && payload["type"] != expected_type
      raise JwtError, "Invalid token type"
    end

    payload
  rescue JWT::ExpiredSignature
    raise JwtError, "Token has expired"
  rescue JWT::DecodeError => e
    raise JwtError, "Invalid token: #{e.message}"
  end
end