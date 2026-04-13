class User < ApplicationRecord
  has_secure_password

  validates :email, presence: true,
                    uniqueness: { case_sensitive: false },
                    format: { with: URI::MailTo::EMAIL_REGEXP }
                    
  validates :full_name, presence: true, 
                        length: { maximum: 35 }, 
                        format: /\A[^0-9`!@#\$%\^&*+_=]+\z/

  validates :password, length: { minimum: 8 }, if: -> { new_record? || password.present? }

end
