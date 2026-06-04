class Category < ApplicationRecord

  belongs_to :user

  validates :name, presence: true,
                   length: { maximum: 35 },
                   format: /[^0-9`!@#\$%\^&*+_=]+/,
                   uniqueness: { scope: :user_id }

end
