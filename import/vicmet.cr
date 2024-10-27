require "http/client"

class Metrics
    def initialize(@host : String)
        @dir = "#{ENV.fetch("QUEUE_DIR", "/tmp")}/metrics.#{@host}"
        Dir.mkdir_p(@dir)
    end

    # Fetch metrics files using rsync.
    def fetch
        remote_file = "nt@#{@host}:/home/nt/queue/"
        local_file = "#{@dir}/"
        args = ["-a", "--remove-source-files", "--include=metrics.*", "--exclude=*", remote_file, local_file]
        Process.run("rsync", args, output: STDOUT, error: STDERR)
    end

    # Yield metrics in Prometheus format.
    def read
        Dir.each_child(@dir) do |file_name|
            next unless file_name.starts_with?("metrics.")
            path_name = File.join(@dir, file_name)
            puts "Reading metrics from #{path_name} (size #{File.size(path_name)})"
            args = ["-d", path_name, "-c", "-q"]
            yield Process.run("zstd", args, output: Process::Redirect::Pipe, error: STDERR) { |p| parse(p.output) }
            File.delete(path_name)
        end
    end

    # Convert metrics from CSV to Prometheus.
    def parse(csv)
        buf = IO::Memory.new
        csv.each_line do |line|
            tokens = line.split("\t")
            case tokens.shift
            when "s"
                # s 1729049727500 IP4 abc def 65008
                ts, ipv, src, dst, port = tokens
                src += "-v6" if ipv == "IP6"
                dst += "-v6" if ipv == "IP6"
                buf << "nt_sent{src=\"#{src}\",dst=\"#{dst}\",port=\"#{port}\"} 1 #{ts}\n"
            when "r"
                # r 1729049727500 106 IP4 TCP abc def 1.2.3.4 65008 237
                ts, delay, ipv, proto, src, dst, ip, port, ttl = tokens
                src += "-v6" if ipv == "IP6"
                dst += "-v6" if ipv == "IP6"
                buf << "nt_received_delay{src=\"#{src}\",dst=\"#{dst}\",proto=\"#{proto}\",port=\"#{port}\"} #{delay} #{ts}\n"
                buf << "nt_received_ttl{src=\"#{src}\",dst=\"#{dst}\",proto=\"#{proto}\",port=\"#{port}\"} #{ttl} #{ts}\n"
            else
                puts "Invalid line: #{line}"
            end
        end
        buf.to_s
    end
end

class VictoriaMetrics
    def initialize(@url : String)
    end

    def send(body)
        url = "#{@url}/api/v1/import/prometheus"
        headers = HTTP::Headers.new
        headers["Content-Type"] = "text/plain"
        headers["Content-Length"] = body.size.to_s
        response = HTTP::Client.post(url, headers, body)
        if response.status_code != 204
            raise "Response: #{response.status_code} #{response.body}"
        end
        puts "Sent #{body.size} bytes to VictoriaMetrics"
    end
end

metrics_db = VictoriaMetrics.new(ENV.fetch("VICMET_URL", "http://127.0.0.1:8428"))

ips = ENV["HOSTS_IPS"].split(" ", remove_empty: true)

ips_metrics = ips.map do |ip|
    Metrics.new(ip)
end

# Fetch metrics using rsync, one per fiber.
ips_metrics.each do |metrics|
    spawn do
        loop do
            begin
                metrics.fetch
            rescue ex
                puts ex.message
            end
            sleep 1
        end
    end
end

# Read metrics from files and send to VictoriaMetrics.
loop do
    sleep 1
    ips_metrics.each do |metrics|
        begin
            metrics.read do |body|
                metrics_db.send(body)
            end
        rescue ex
            puts ex.message
        end
    end
end
