Rails.application.routes.draw do
  namespace :api do 
    namespace :v1 do 
      post "/signin", to: "sessions#signin"
      post "/signup", to: "sessions#signup"
      post "/refresh_token", to: "sessions#refresh_token"
    end
  end
end
