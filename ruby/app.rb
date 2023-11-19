require 'sinatra/base'
# require 'mysql2'
require 'rack-flash'
require 'shellwords'
require 'rack/session/dalli'

# require 'mysql2-cs-bind'

# TODO: Sinatra app内で include SentryMethods する
require_relative "./config/sentry_methods"

# 必要に応じて使う
# require "mysql2-nested_hash_bind"
# require_relative "./config/hash_group_by_prefix"
# require_relative "./config/mysql_methods"
# require_relative "./config/oj_encoder"
# require_relative "./config/oj_to_json_patch"
# require_relative "./config/redis_methods"
# require_relative "./config/sidekiq"
# require_relative "./config/sidekiq_methods"

# TODO: 終了直前にコメントアウトする
require_relative "./config/enable_monitoring"

# NOTE: enable_monitoringでddtraceとdatadog_thread_tracerをrequireしてるのでenable_monitoringをrequireした後でrequireする必要がある
# require_relative "./config/thread_helper"

require_relative "./lib/db_helper"

module Isuconp
  class App < Sinatra::Base
    include SentryMethods
    # using Mysql2::NestedHashBind::QueryExtension

    disable :logging
    use Rack::Session::Dalli, autofix_keys: true, secret: ENV['ISUCONP_SESSION_SECRET'] || 'sendagaya', memcache_server: ENV['ISUCONP_MEMCACHED_ADDRESS'] || 'localhost:11211'
    use Rack::Flash
    set :public_folder, File.expand_path('../../public', __FILE__)

    UPLOAD_LIMIT = 10 * 1024 * 1024 # 10mb

    POSTS_PER_PAGE = 20

    PUBLIC_DIR = "#{__dir__}/../public"

    helpers DbHelper

    helpers do
      # def config
      #   @config ||= {
      #     db: {
      #       host: ENV['ISUCONP_DB_HOST'] || 'localhost',
      #       port: ENV['ISUCONP_DB_PORT'] && ENV['ISUCONP_DB_PORT'].to_i,
      #       username: ENV['ISUCONP_DB_USER'] || 'root',
      #       password: ENV['ISUCONP_DB_PASSWORD'],
      #       database: ENV['ISUCONP_DB_NAME'] || 'isuconp',
      #     },
      #   }
      # end
      #
      # def db
      #   return Thread.current[:isuconp_db] if Thread.current[:isuconp_db]
      #   client = Mysql2::Client.new(
      #     host: config[:db][:host],
      #     port: config[:db][:port],
      #     username: config[:db][:username],
      #     password: config[:db][:password],
      #     database: config[:db][:database],
      #     encoding: 'utf8mb4',
      #     reconnect: true,
      #   )
      #   client.query_options.merge!(symbolize_keys: true, database_timezone: :local, application_timezone: :local)
      #   Thread.current[:isuconp_db] = client
      #   client
      # end

      def db_initialize
        sql = []
        sql << 'DELETE FROM users WHERE id > 1000'
        sql << 'DELETE FROM posts WHERE id > 10000'
        sql << 'DELETE FROM comments WHERE id > 100000'
        sql << 'UPDATE users SET del_flg = 0'
        sql << 'UPDATE users SET del_flg = 1 WHERE id % 50 = 0'
        sql.each do |s|
          db.xquery(s) # rubocop:disable Isucon/Mysql2/NPlusOneQuery 初期化なので無視する
        end
      end

      def try_login(account_name, password)
        # TODO: Remove needless columns if necessary
        user = db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM users WHERE account_name = ? AND del_flg = 0',account_name).first

        if user && calculate_passhash(user[:account_name], password) == user[:passhash]
          return user
        elsif user
          return nil
        else
          return nil
        end
      end

      def validate_user(account_name, password)
        if !(/\A[0-9a-zA-Z_]{3,}\z/.match(account_name) && /\A[0-9a-zA-Z_]{6,}\z/.match(password))
          return false
        end

        return true
      end

      def digest(src)
        # opensslのバージョンによっては (stdin)= というのがつくので取る
        # `printf "%s" #{Shellwords.shellescape(src)} | openssl dgst -sha512 | sed 's/^.*= //'`.strip

        Digest::SHA512.hexdigest(src)
      end

      def calculate_salt(account_name)
        digest account_name
      end

      def calculate_passhash(account_name, password)
        digest "#{password}:#{calculate_salt(account_name)}"
      end

      def get_session_user()
        if session[:user]
          # TODO: Remove needless columns if necessary
          db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` = ?',
            session[:user][:id]
          ).first
        else
          nil
        end
      end

      # def make_posts(results, all_comments: false)
      #   posts = []
      #   results.to_a.each do |post|
      #     post[:comment_count] = db.xquery('SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?',
      #       post[:id]
      #     ).first[:count]
      #
      #     query = 'SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC'
      #     unless all_comments
      #       query += ' LIMIT 3'
      #     end
      #     comments = db.xquery(query,
      #       post[:id]
      #     ).to_a
      #     comments.each do |comment|
      #       # TODO: Remove needless columns if necessary
      #       comment[:user] = db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` = ?',
      #         comment[:user_id]
      #       ).first
      #     end
      #     post[:comments] = comments.reverse
      #
      #     # TODO: Remove needless columns if necessary
      #     post[:user] = db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` = ?',
      #       post[:user_id]
      #     ).first
      #
      #     posts.push(post) if post[:user][:del_flg] == 0
      #     break if posts.length >= POSTS_PER_PAGE
      #   end
      #
      #   posts
      # end

      def make_posts(results, all_comments: false)
        post_ids = results.map { |post| post[:id] }

        # 一括でコメント数を取得
        comment_counts = db.xquery('SELECT post_id, COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN (?) GROUP BY post_id', post_ids).to_h { |row| [row[:post_id], row[:count]] }

        # 一括でコメントを取得
        comments_query = 'SELECT * FROM `comments` WHERE `post_id` IN (?) ORDER BY `created_at` DESC'
        comments_query += ' LIMIT 3' unless all_comments
        comments = db.xquery(comments_query, post_ids).group_by { |comment| comment[:post_id] }

        # 一括でユーザー情報を取得
        user_ids = results.map { |post| post[:user_id] }
        user_ids += comments.values.flatten.map { |comment| comment[:user_id] }
        user_ids = user_ids.uniq

        users = db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `id` IN (?)', user_ids).to_h { |row| [row[:id], row] }

        posts = results.filter_map do |post|
          post_id = post[:id]

          post[:comment_count] = comment_counts[post_id].to_i

          post[:comments] = comments[post_id].to_a.reverse.map do |comment|
            comment[:user] = users[comment[:user_id]]
            comment
          end

          post[:user] = users[post[:user_id]]

          if post.dig(:user, :del_flg) == 0
            post
          else
            nil
          end
        end

        if posts.length > POSTS_PER_PAGE
          posts = posts[0...POSTS_PER_PAGE]
        end

        posts
      end

      def image_url(post)
        ext = ""
        if post[:mime] == "image/jpeg"
          ext = ".jpg"
        elsif post[:mime] == "image/png"
          ext = ".png"
        elsif post[:mime] == "image/gif"
          ext = ".gif"
        end

        "/image/#{post[:id]}#{ext}"
      end
    end

    get '/initialize' do
      db_initialize

      # 画像を初期化
      # rubocop:disable Isucon/Shell/System
      system("rm -rf #{PUBLIC_DIR}/image/*", exception: true)
      system("cp #{PUBLIC_DIR}/image_origin/* #{PUBLIC_DIR}/image", exception: true)
      # rubocop:enable Isucon/Shell/System

      return 200
    end

    get '/login' do
      if get_session_user()
        redirect '/', 302
      end
      erb :login, layout: :layout, locals: { me: nil }
    end

    post '/login' do
      if get_session_user()
        redirect '/', 302
      end

      user = try_login(params['account_name'], params['password'])
      if user
        session[:user] = {
          id: user[:id]
        }
        session[:csrf_token] = SecureRandom.hex(16)
        redirect '/', 302
      else
        flash[:notice] = 'アカウント名かパスワードが間違っています'
        redirect '/login', 302
      end
    end

    get '/register' do
      if get_session_user()
        redirect '/', 302
      end
      erb :register, layout: :layout, locals: { me: nil }
    end

    post '/register' do
      if get_session_user()
        redirect '/', 302
      end

      account_name = params['account_name']
      password = params['password']

      validated = validate_user(account_name, password)
      if !validated
        flash[:notice] = 'アカウント名は3文字以上、パスワードは6文字以上である必要があります'
        redirect '/register', 302
        return
      end

      user = db.xquery('SELECT 1 FROM users WHERE `account_name` = ?',account_name).first
      if user
        flash[:notice] = 'アカウント名がすでに使われています'
        redirect '/register', 302
        return
      end

      query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)'
      db.xquery(query,
        account_name,
        calculate_passhash(account_name, password)
      )

      session[:user] = {
        id: db.last_id
      }
      session[:csrf_token] = SecureRandom.hex(16)
      redirect '/', 302
    end

    get '/logout' do
      session.delete(:user)
      redirect '/', 302
    end

    get '/' do
      me = get_session_user()

      # results = db.query('SELECT `id`, `user_id`, `body`, `created_at`, `mime` FROM `posts` ORDER BY `created_at` DESC')

      results = db.query(<<~SQL)
        SELECT `posts`.`id`, `posts`.`user_id`, `posts`.`body`, `posts`.`created_at`, `posts`.`mime`
        FROM `posts`
        INNER JOIN users ON users.id = `posts`.`user_id`
        WHERE users.del_flg = 0
        ORDER BY `created_at` DESC LIMIT #{POSTS_PER_PAGE}
      SQL
      posts = make_posts(results)

      erb :index, layout: :layout, locals: { posts: posts, me: me }
    end

    get '/@:account_name' do
      # TODO: Remove needless columns if necessary
      user = db.xquery('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `account_name` = ? AND `del_flg` = 0',
        params[:account_name]
      ).first

      if user.nil?
        return 404
      end

      results = db.xquery('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC',
        user[:id]
      )
      posts = make_posts(results)

      comment_count = db.xquery('SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?',
        user[:id]
      ).first[:count]

      post_ids = db.xquery('SELECT `id` FROM `posts` WHERE `user_id` = ?',
        user[:id]
      ).map{|post| post[:id]}
      post_count = post_ids.length

      commented_count = 0
      if post_count > 0
        placeholder = (['?'] * post_ids.length).join(",")
        commented_count = db.xquery("SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN (#{placeholder})",
          *post_ids
        ).first[:count]
      end

      me = get_session_user()

      erb :user, layout: :layout, locals: { posts: posts, user: user, post_count: post_count, comment_count: comment_count, commented_count: commented_count, me: me }
    end

    get '/posts' do
      max_created_at = params['max_created_at']

      # results = db.xquery('SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC',
      #   max_created_at.nil? ? nil : Time.iso8601(max_created_at).localtime
      # )

      created_at = max_created_at.nil? ? nil : Time.iso8601(max_created_at).localtime
      results = db.xquery(<<~SQL, created_at)
        SELECT `posts`.`id`, `posts`.`user_id`, `posts`.`body`, `posts`.`created_at`, `posts`.`mime`
        FROM `posts`
        INNER JOIN users ON users.id = `posts`.`user_id`
        WHERE users.del_flg = 0
        AND `posts`.`created_at` <= ?
        ORDER BY `posts`.`created_at` DESC LIMIT #{POSTS_PER_PAGE}
      SQL

      posts = make_posts(results)

      erb :posts, layout: false, locals: { posts: posts }
    end

    get '/posts/:id' do
      # TODO: Remove needless columns if necessary
      results = db.xquery('SELECT `id`, `user_id`, `mime`, `imgdata`, `body`, `created_at` FROM `posts` WHERE `id` = ?',
        params[:id]
      )
      posts = make_posts(results, all_comments: true)

      return 404 if posts.length == 0

      post = posts[0]

      me = get_session_user()

      erb :post, layout: :layout, locals: { post: post, me: me }
    end

    post '/' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      if params['file']
        mime = ''
        ext = ""
        # 投稿のContent-Typeからファイルのタイプを決定する
        if params["file"][:type].include? "jpeg"
          mime = "image/jpeg"
          ext = "jpg"
        elsif params["file"][:type].include? "png"
          mime = "image/png"
          ext = "png"
        elsif params["file"][:type].include? "gif"
          mime = "image/gif"
          ext = "gif"
        else
          flash[:notice] = '投稿できる画像形式はjpgとpngとgifだけです'
          redirect '/', 302
        end

        if params['file'][:tempfile].read.length > UPLOAD_LIMIT
          flash[:notice] = 'ファイルサイズが大きすぎます'
          redirect '/', 302
        end

        params['file'][:tempfile].rewind

        db.xquery(<<~SQL, me[:id], params["body"], "", mime)
          INSERT INTO `posts` (`user_id`, `body`, `imgdata`, `mime`) VALUES (?,?,?,?)
        SQL

        # FIXME: ncoding::CompatibilityError - incompatible character encodings: UTF-8 and ASCII-8BIT:
        # db.prepare(query).execute(
        # # db.xquery(query,
        #   me[:id],
        #   mime,
        #   params["file"][:tempfile].read,
        #   params["body"],
        # )

        pid = db.last_id

        # 画像ファイルはpublic/image/に保存する
        File.open("#{PUBLIC_DIR}/image/#{pid}.#{ext}", 'wb') do |f|
          f.write(params['file'][:tempfile].read)
        end

        redirect "/posts/#{pid}", 302
      else
        flash[:notice] = '画像が必須です'
        redirect '/', 302
      end
    end

    # get '/image/:id.:ext' do
    #   if params[:id].to_i == 0
    #     return ""
    #   end
    #
    #   # TODO: Remove needless columns if necessary
    #   post = db.xquery('SELECT `id`, `user_id`, `mime`, `imgdata`, `body`, `created_at` FROM `posts` WHERE `id` = ?',params[:id].to_i).first
    #
    #   if (params[:ext] == "jpg" && post[:mime] == "image/jpeg") ||
    #       (params[:ext] == "png" && post[:mime] == "image/png") ||
    #       (params[:ext] == "gif" && post[:mime] == "image/gif")
    #     headers['Content-Type'] = post[:mime]
    #     return post[:imgdata]
    #   end
    #
    #   return 404
    # end

    post '/comment' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if params["csrf_token"] != session[:csrf_token]
        return 422
      end

      unless /\A[0-9]+\z/.match?((params['post_id']))
        return 'post_idは整数のみです'
      end
      post_id = params['post_id']

      query = 'INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)'
      db.xquery(query,
        post_id,
        me[:id],
        params['comment']
      )

      redirect "/posts/#{post_id}", 302
    end

    get '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/login', 302
      end

      if me[:authority] == 0
        return 403
      end

      # TODO: Remove needless columns if necessary
      users = db.query('SELECT `id`, `account_name`, `passhash`, `authority`, `del_flg`, `created_at` FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC')

      erb :banned, layout: :layout, locals: { users: users, me: me }
    end

    post '/admin/banned' do
      me = get_session_user()

      if me.nil?
        redirect '/', 302
      end

      if me[:authority] == 0
        return 403
      end

      if params['csrf_token'] != session[:csrf_token]
        return 422
      end

      query = 'UPDATE `users` SET `del_flg` = ? WHERE `id` = ?'

      params['uid'].each do |id|
        db.xquery(query,1, id.to_i) # rubocop:disable Isucon/Mysql2/NPlusOneQuery あまり呼ばれないのであとで直す
      end

      redirect '/admin/banned', 302
    end
  end
end
