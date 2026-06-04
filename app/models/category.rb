class Category < ApplicationRecord

  mount_uploader :icon, IconUploader

  belongs_to :user

  validates :name, presence: true,
                   length: { maximum: 35 },
                   format: /[^0-9`!@#\$%\^&*+_=]+/,
                   uniqueness: { scope: :user_id }

  def as_json(*)
    super(only: [:id, :name]).merge(icon: icon.url)
  end
end
