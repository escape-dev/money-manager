class Api::V1::CategoriesController < ApplicationController
  before_action :authenticate_request!
  before_action :set_category, only: %i[ show ]
  
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

  def show 
    response_ok(@category, :ok)
  end

  private 

  def category_params
    params.permit(:name, :icon)
  end

  def set_category 
    @category = Category.find_by(id: params[:id], user_id: @current_user.id)

    response_error("Category not found", :not_found) unless @category
  end
end
