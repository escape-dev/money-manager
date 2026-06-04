class Api::V1::CategoriesController < ApplicationController
  before_action :authenticate_request!
  
  def index
    @categories = Category.where(user_id: @current_user.id)
    
    response_ok(@categories.as_json)
  end

  def create
    @category = Category.new(category_params.merge(user_id: @current_user.id))

    if @category.save
      response_ok(@category.as_json(only: [:id, :name]), :created)
    else
      response_error(@category.errors.full_messages.join(", "), :unprocessable_entity)
    end
  end

  private 

  def category_params
    params.permit(:name, :icon)
  end
end
