class IconUploader < CarrierWave::Uploader::Base
  include CarrierWave::MiniMagick

  # Optimize image processing in a single pass to save CPU and memory,
  # and strip metadata to reduce file size and protect privacy.
  process :process_icon

  # Limit file sizes to prevent Denial of Service (DoS) attacks
  def size_range
    1..1.megabyte
  end

  # Restrict allowed file extensions
  def extension_allowlist
    %w(png)
  end

  # Restrict allowed MIME types to prevent content spoofing
  def content_type_allowlist
    [%r{image/png}]
  end

  # Override the directory where uploaded files will be stored.
  def store_dir
    "uploads/#{model.class.to_s.underscore}/#{mounted_as}/#{model.id}"
  end

  private

  # Resizes and crops the image to fill 50x50, stripping metadata in the same execution.
  def process_icon
    manipulate! do |img|
      img.combine_options do |cmd|
        cmd.strip
        cmd.resize "50x50^"
        cmd.gravity "Center"
        cmd.crop "50x50+0+0"
      end
      img
    end
  end
end
