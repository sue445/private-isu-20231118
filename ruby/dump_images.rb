require_relative "lib/db_helper"

include DbHelper

posts = db.xquery('SELECT `id`, `mime`, `imgdata` FROM `posts`')
posts.each do |post|
  ext =
    case post[:mime]
    when "image/jpeg"
      "jpg"
    when "image/png"
      "png"
    when "image/gif"
      "gif"
    end

  filename = "#{post[:id]}.#{ext}"
  File.open(File.join(__dir__, "..", "public", "image_origin", filename), "wb") do |f|
    f.write(post[:imgdata])
  end
end
