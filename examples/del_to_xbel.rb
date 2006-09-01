#!/usr/bin/env ruby

# load bindings
require 'rubilicious'

# check command-line arguments
unless ARGV.size == 3
  $stderr.puts "Usage: $0 [user] [pass] [output_file]"
  exit -1
end

# get command-line arguments
user, pass, path = ARGV

# open output fileC, connect to rubilicious, save 
File::open(path, 'w') do |file| 
  # connect to rubilicious
  r = Rubilicious.new(user, pass)
  
  # save recent entries to output file
  file.puts Rubilicious.to_xbel(r.recent)
end
