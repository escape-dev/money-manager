class Api::V1::UsersController < ApplicationController
  before_action :authenticate_request!

  def me 
    response_ok(@current_user)
  end

end
