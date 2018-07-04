#!/usr/bin/env ruby

require 'yaml'
require 'open-uri'
require 'openssl'
require 'open3'
require 'fileutils'
require 'find'

if Process.euid != 0
  puts "This script has to be run as root"
  exit
end

def get_digest(checksum_method)
  case checksum_method
    when 'sha256'
      digest = OpenSSL::Digest::SHA256.new
    else
      raise "Did not recognise checksum_method"
  end
  digest
end

def digest(data, checksum_method)
  digest = get_digest(checksum_method)
  digest.hexdigest(data)
end

def digest_file(filename, checksum_method)
  digest = get_digest(checksum_method)
  File.open(filename, 'rb') do |io|
    while (buf = io.read(4096)) && buf.length > 0
      digest.update(buf)
    end
  end
  digest.hexdigest
end

def generate_tmp_filename
  "/tmp/filegrabber_#{Process.pid}_#{rand(500)}"
end

def validate_data(data, checksum_method, checksum)
  digest = digest(data, checksum_method)
  checksum.eql?(digest)
end

def import_rpm_key(config, data)
  tmpfile = generate_tmp_filename
  File.write(tmpfile, data)
  stdout, status = Open3.capture2("#{config['rpm']} --import #{tmpfile}")
  File.delete(tmpfile)
  raise "Import failed" if status != 0
end

def process_rpm_key(config, url, checksum_method, expected_checksum)
  data = open(url).read
  if validate_data(data, checksum_method, expected_checksum)
    puts "Key: Importing #{url} to the system rpm keyring"
    import_rpm_key(config, data)
  else
    raise "RPM Key '#{url}' does not match checksum."
  end
end

def import_keys(config, keys)
  keys.each do |key|
    case key['type']
      when 'rpm'
        process_rpm_key(config, key['url'], key['checksum_method'], key['checksum'])
      else
        raise "Unknown key type '#{key['type']}'"
    end
  end
end

def generate_yum_config(url, name)
  <<-eos
[main]
reposdir=/dev/null

[#{name}]
name=#{name}
baseurl=#{url}
  eos
end

def synchronise_yum_repo(config, yumconfig, targetdir)
  sync_command = "#{config['reposync']} -c #{yumconfig} -p #{targetdir}"
  sync_command += " -d" if config['yum_delete_missing_upstream']
  stdout, status = Open3.capture2(sync_command)
  raise "Sync failed" if status != 0
  # TODO: be more descriptive of the error
end

def validate_yum_repo(config, targetdir)
  Find.find(targetdir) do |f|
    if f =~ /.*\.rpm$/
      stdout, status = Open3.capture2("#{config['rpm']} -Kv #{f}")
      if status != 0
        puts "#{f} signature verification failed"
        if config['yum_delete_on_signature_verify_fail']
          puts "Deleting #{f}"
          File.delete(f) 
        end
      end
    end
  end
end

def import_repos(config, repos)
  repos.each do |repo|
    case repo['type']
      when 'yum'
        process_yum_repo(config, repo['name'], repo['url'], repo['path'])
      else
        raise "Unknown repo type '#{repo['type']}'"
    end
  end
end

def process_yum_repo(config, name, url, path)
  # generate a yum configuration
  yumconfig = generate_tmp_filename
  File.write(yumconfig, generate_yum_config(url, name))
  targetdir = "#{config['basedir']}/#{path}"
  FileUtils.mkdir_p(targetdir)
  puts "Yum: Synchronising #{url} to #{targetdir}/#{name}"
  synchronise_yum_repo(config, yumconfig, targetdir)
  puts "Yum: Verifying signatures #{targetdir}/#{name}"
  validate_yum_repo(config, targetdir)
  File.delete(yumconfig)
end

def download_file(target, url)
  uri = URI(url)
  File.open(target, "wb") do |save|
    open(url, "rb") do |read|
      save.write(read.read)
    end
  end
end

def validate_file(filename, checksum_method, checksum)
  digest = digest_file(filename, checksum_method)
  checksum.eql?(digest)
end

def process_file(config, name, url, path, checksum_method, checksum)
  targetdir = "#{config['basedir']}/#{path}"
  finaldestination = "#{targetdir}/#{name}"
  if File.exists?(finaldestination)
      if validate_file(finaldestination, checksum_method, checksum)
        puts "File: #{name} is good, skipping."
        return
      else
        puts "File: #{name} exists but the checksum is bad, redownloading."
      end
  end
  tmpfile = generate_tmp_filename
  # write file to disk in a temporary location
  puts "File: Downloading #{name}"
  download_file(tmpfile, url)
  puts "File: Verifying checksum on #{name}"
  if validate_file(tmpfile, checksum_method, checksum)
    FileUtils.mkdir_p(targetdir)
    puts "File: Checksum validation successful, moving to #{finaldestination}"
    FileUtils.mv(tmpfile, finaldestination)
  else
    puts "Checksum validation failed on #{name}. Not moving to the final destination"
    File.delete(tmpfile)
  end
end

def import_files(config, files)
  files.each do |file|
    process_file(config, file['name'], file['url'], file['path'], file['checksum_method'], file['checksum'])
  end
end


config = YAML.load(File.read('config.yaml'))
import_keys(config['config'], config['keys'])
import_repos(config['config'], config['repos'])
import_files(config['config'], config['files'])