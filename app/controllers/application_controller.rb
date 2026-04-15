class ApplicationController < ActionController::API
  BEARER_PATTERN = /\ABearer /i.freeze

  def authenticate_request! 
    payload = AuthService.decode_access_token(bearer_token)
    @current_user = User.find_by(id: payload["user_id"])
    
    response_error("You need to sign in to continue", :unauthorized) unless @current_user
  rescue JwtError => e 
    response_error(e.message, :unauthorized)
  end

  def response_ok(data, status = :ok)
    render json: { message: "success", data: data }, status: status
  end

  def response_error(message, status = :bad_request)
    render json: { message: message }, status: status
  end

  private 

  def bearer_token
    header = request.headers["Authorization"]
    return nil unless header&.match?(BEARER_PATTERN)

    header.split(" ", 2).last.presence
  end
end
