class Api::V1::SessionsController < ApplicationController
  def signup
    @user = User.new(session_params)

    if @user.save 
      response_ok(@user.as_json(only: [:id, :email, :name, :created_at]), :created)
    else
      response_error(@user.errors.full_messages.join(", "), :unprocessable_entity)
    end
  end

  def signin
    @user = User.find_by(email: session_params[:email])

    if @user&.authenticate(session_params[:password])
      response_ok(AuthService.generate_token_pair(@user.id))
    else
      response_error("Invalid email or password", :unprocessable_entity)
    end
  end

  def refresh_token
    payload = AuthService.decode_refresh_token(params[:refresh_token])
    user = User.find_by(id: payload["user_id"])

    if user 
      response_ok(AuthService.generate_token_pair(user.id))
    else 
      response_error("User not found", :unauthorized)
    end
  rescue JwtError => e
    response_error(e.message, :unauthorized)
  end

  private

  def session_params
    params.require(:user).permit(:name, :email, :password)
  end
end
