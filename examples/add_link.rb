#!/usr/bin/env ruby

require 'rubilicious'

# check command-line arguments
if ARGV < 4
  $stderr.puts "Usage: $0 [user] [pass] [url] [title] <desc> <tags>"
end

# grab command-line arguments
user, pass, url, title, desc, tags = ARGV

# connect and add url
r = Rubilicious.new(user, pass)
r.add(url, title, desc, tags)

