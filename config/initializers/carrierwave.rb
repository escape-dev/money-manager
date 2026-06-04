CarrierWave.configure do |config|
  case Rails.env.to_sym
  when :production
    require "carrierwave/storage/fog"

    config.storage = :fog
    config.fog_provider = "fog/aws"
    config.fog_directory = ENV["S3_BUCKET"]
    config.fog_public = true

    config.fog_credentials = {
      provider: "AWS",
      aws_access_key_id: ENV["S3_ACCESS_KEY"],
      aws_secret_access_key: ENV["S3_SECRET_KEY"],
      host: ENV["S3_HOST"],
      endpoint: ENV["S3_ENDPOINT"],
      path_style: true
    }

  when :test
    config.storage = :file
    config.enable_processing = false
    config.root = Rails.root.join("tmp")
    config.cache_dir = "uploads/tmp"

  else
    config.storage = :file
    config.enable_processing = true
  end
end