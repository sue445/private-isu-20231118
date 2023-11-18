# ISUCON用汎用デプロイスクリプト

# Requirements
# * ruby
# * curl
# * gh
#   * https://github.com/cli/cli
#   * gh auth login
#
# Usage
# * rake

require "json"

# デプロイ先のサーバ
HOSTS = {
  # host01: "isucon-01",
  # host02: "isucon-02",
  # host03: "isucon-03",
}

INITIALIZE_ENDPOINT = "http://#{HOSTS[:host01]}/initialize"

# デプロイ先のカレントディレクトリ
CURRENT_DIR = "/home/isucon/isutrain"

# rubyアプリのディレクトリ
RUBY_APP_DIR = "/home/isucon/APP_NAME/webapp/ruby"

# アプリのservice名
# NOTE: `sudo systemctl list-unit-files --type=service | grep isu` などで調べる
APP_SERVICE_NAME = "isuxxxxx-ruby.service"

# デプロイを記録するissue
GITHUB_REPO     = "sue445/isuconXX-qualify"
GITHUB_ISSUE_ID = 1

RUBY_VERSION_PATH = "#{__dir__}/webapp/ruby/.ruby-version"

ruby_version = File.read(RUBY_VERSION_PATH).strip

BUNDLE = "/home/isucon/local/ruby/versions/#{ruby_version}/bin/bundle"

def exec(ip_address, command, cwd: CURRENT_DIR)
  sh %Q(ssh isucon@#{ip_address} 'cd #{cwd} && #{command}')
end

def exec_service(ip_address, service:, enabled:, status: true)
  if enabled
    exec ip_address, "sudo systemctl restart #{service}"
    exec ip_address, "sudo systemctl enable #{service}"

    if status
      exec ip_address, "sudo systemctl status #{service}"
    end
  else
    exec ip_address, "sudo systemctl stop #{service}"
    exec ip_address, "sudo systemctl disable #{service}"
  end
end

def current_branch
  @current_branch ||= `git branch | grep '* '`.gsub(/^\*/, "").strip
end

namespace :deploy do
  HOSTS.each do |name, ip_address|
    desc "Deploy to #{name}"
    task name do
      puts "[deploy:#{name}] START"

      # common
      exec ip_address, "git fetch"
      exec ip_address, "git checkout #{current_branch}"
      exec ip_address, "git reset --hard origin/#{current_branch}" # force push対策

      exec ip_address, "sudo cp infra/systemd/#{APP_SERVICE_NAME} /etc/systemd/system/#{APP_SERVICE_NAME}"
      # exec ip_address, "sudo cp infra/systemd/isucon-sidekiq.service /etc/systemd/system/isucon-sidekiq.service"

      # systemdの更新後にdaemon-reloadする
      exec ip_address, "sudo systemctl daemon-reload"

      # TODO: 終了10分前にdisableすること！！！！！！
      exec_service ip_address, service: "datadog-agent", enabled: true
      exec_service ip_address, service: "td-agent", enabled: true

      # FIXME: datadog-agentをdisableにしてもなぜかreboot後に起動することがあるので確実に止めるためにアンインストールする
      # exec ip_address, "sudo apt-get remove -y datadog-agent"

      # mysql, mariadb
      case name
      when :host01
        # exec ip_address, "sudo cp infra/mysql/isucon.cnf /etc/mysql/conf.d/isucon.cnf"
        # exec ip_address, "sudo cp infra/mysql/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf "
        # exec ip_address, "sudo mysqld --verbose --help > /dev/null"
        # TODO: mariadbで動いてないか確認する
        # exec_service ip_address, service: "mysql", enabled: true
        # exec_service ip_address, service: "mariadb", enabled: true
      else
        # exec_service ip_address, service: "mysql", enabled: false
        # exec_service ip_address, service: "mariadb", enabled: false
      end

      # nginx
      case name
      when :host01
        # exec ip_address, "sudo cp infra/nginx/nginx.conf /etc/nginx/nginx.conf"
        # exec ip_address, "sudo nginx -t"
        # exec ip_address, "sudo chmod 644 /var/log/nginx/*.log"
        # exec_service ip_address, service: "nginx", enabled: true
      else
        # exec_service ip_address, service: "nginx", enabled: false
      end

      # app
      case name
      when :host01
        # exec ip_address, "#{BUNDLE} config set --local path 'vendor/bundle'", cwd: RUBY_APP_DIR
        # exec ip_address, "#{BUNDLE} config set --local jobs $(nproc)", cwd: RUBY_APP_DIR
        # exec ip_address, "#{BUNDLE} config set --local without development test", cwd: RUBY_APP_DIR

        # exec ip_address, "#{BUNDLE} install", cwd: RUBY_APP_DIR
        # FIXME: ruby 3.2.0-devだとddtraceのnative extensionのbuildに失敗するのでこっちを使う
        # exec ip_address, "DD_PROFILING_NO_EXTENSION=true #{BUNDLE} install", cwd: RUBY_APP_DIR

        # exec_service ip_address, service: APP_SERVICE_NAME, enabled: true
      else
        # exec_service ip_address, service: APP_SERVICE_NAME, enabled: false
      end

      # redis
      case name
      when :host01
        # exec ip_address, "sudo cp infra/redis/redis.conf /etc/redis/redis.conf"
        # exec_service ip_address, service: "redis-server", enabled: true
        # exec ip_address, "redis-cli flushall"
      else
        # exec_service ip_address, service: "redis-server", enabled: false
      end

      # sidekiq
      case name
      when :host01
        # exec ip_address, "#{BUNDLE} config set --local path 'vendor/bundle'", cwd: RUBY_APP_DIR
        # exec ip_address, "#{BUNDLE} config set --local jobs $(nproc)", cwd: RUBY_APP_DIR
        # exec ip_address, "#{BUNDLE} config set --local without development test", cwd: RUBY_APP_DIR

        # exec ip_address, "#{BUNDLE} install", cwd: RUBY_APP_DIR
        # FIXME: ruby 3.2.0-devだとddtraceのnative extensionのbuildに失敗するのでこっちを使う
        # exec ip_address, "DD_PROFILING_NO_EXTENSION=true #{BUNDLE} install", cwd: RUBY_APP_DIR

        # exec_service ip_address, service: "isucon-sidekiq", enabled: true
      else
        # exec_service ip_address, service: "isucon-sidekiq", enabled: false
      end

      # docker-compose
      case name
      when :host01
        # exec ip_address, "docker-compose -f webapp/docker-compose.yml -f webapp/docker-compose.ruby.yml down"
        # exec ip_address, "docker-compose -f webapp/docker-compose.yml up -d --build"
      else
        # exec ip_address, "docker-compose -f webapp/docker-compose.yml -f webapp/docker-compose.ruby.yml down"
      end

      puts "[deploy:#{name}] END"
    end
  end
end

desc "Prepare for deploy"
task :setup do
  sh "git push"
end

desc "Deploy to all hosts"
multitask :deploy => HOSTS.keys.map { |name| "deploy:#{name}" }

desc "POST /initialize"
task :initialize do
  sh "curl -X POST --retry 3 --fail #{INITIALIZE_ENDPOINT}"
end

desc "Record current commit to issue"
task :record do
  revision = `git rev-parse --short HEAD`.strip

  current_tag = [
    Time.now.strftime("%Y%m%d-%H%M%S"),
    `whoami`.strip
  ].join("-")

  message = ":rocket: Deployed #{revision} [#{current_tag}](https://github.com/#{GITHUB_REPO}/releases/tag/#{current_tag})"

  # 直前のリリースのtagを取得する
  before_tag = `git tag | tail -n 1`.strip

  unless before_tag.empty?
    message << " ([compare](https://github.com/#{GITHUB_REPO}/compare/#{before_tag}...#{current_tag}))"
  end

  sh "git tag -a #{current_tag} -m 'Release #{current_tag}'"
  sh "git push --tags"

  if %w(main master).include?(current_branch)
    # issueにコメントするのはmainブランチやmasterブランチの時だけ
    sh "gh issue comment --repo #{GITHUB_REPO} #{GITHUB_ISSUE_ID} --body '#{message}'"
  else
    # mainブランチやmasterブランチ以外であればPRであるとみなしてPRにもコメントする
    res = JSON.parse(`gh pr list --repo #{GITHUB_REPO} --head #{current_branch} --json number`)
    unless res.empty?
      sh "gh pr comment --repo #{GITHUB_REPO} #{res[0]["number"]} --body '#{message}'"
    end
  end
end

task :all => [:setup, :deploy, :initialize, :record]

task :default => :all
