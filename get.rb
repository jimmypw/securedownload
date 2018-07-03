require 'yaml'
require 'net/http'
require 'openssl'
require 'uri'
require 'open3'

if Process.euid != 0
  puts "This script has to be run as root"
  exit
end

def digest(data, digest_method)
  case digest_method
    when 'sha256'
      digest = OpenSSL::Digest::SHA256.new
  end
  digest.hexdigest(data)
end

def validate_file(data, digest_method, checksum)
  digest = digest(data, digest_method)
  checksum.eql?(digest)
end

def import_rpm_key(data)
  tmpfile = "/tmp/rpm_key_#{Process.pid}_#{rand(500)}"
  File.write(tmpfile, data)
  stdout, status = Open3.capture2("/usr/bin/rpm --import #{tmpfile}")
  File.delete(tmpfile)
  raise "Import failed" if status != 0
end

def process_rpm_key(url, digest_method, expected_checksum)
  data = Net::HTTP.get(URI(url))
  if validate_file(data, digest_method, expected_checksum)
    puts "Importing: #{url}"
    import_rpm_key(data)
  else
    raise "RPM Key #{url} does not match checksum."
  end
end

def import_keys(keys)
  keys.each do |key|
    case key['type']
      when 'rpm'
        process_rpm_key(key['url'], key['digest_method'], key['checksum'])
    end
  end
end

config = YAML.load(File.read('config.yaml'))
import_keys(config['keys'])