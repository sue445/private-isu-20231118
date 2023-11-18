# Sentryの便利メソッド
require "sentry-ruby"
require "open3"

module SentryMethods
  # ブロック内でエラーが起きた時に明示的にSentryにエラーを送信してから再raiseする
  #
  # @raise RuntimeError ブロック内で発生したエラー
  def with_sentry
    yield
  rescue => error
    Sentry.capture_exception(error)
    raise error
  end

  # 外部コマンドを実行し、失敗したら標準出力と標準エラーを付与してSentryに送信する
  #
  # @param command [String]
  #
  # @return コマンド実行時の標準出力
  #
  # @raise RuntimeError 外部コマンドが失敗した
  def system_with_sentry(command)
    stdout, stderr, status = Open3.capture3(command)

    unless status.success?
      Sentry.set_extras(
        stdout: stdout,
        stderr: stderr,
      )
      raise "`#{command}` is failed"
    end

    stdout
  end
end
