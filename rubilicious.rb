#!/usr/bin/env ruby

#######################################################################
# Rubilicious - Delicious (http://del.icio.us/) bindings for Ruby     #
# by Paul Duncan <pabs@pablotron.org>                                 #
#                                                                     #
#                                                                     #
# For the latest version of this software, Please see the Rubilicious #
# page at http://www.pablotron.org/software/rubilicious/.             #
#                                                                     #
#                                                                     #
# Copyright (C)  2004 Paul Duncan.                                    #
#                                                                     #
# Permission is hereby granted, free of charge, to any person         #
# obtaining a copy of this software and associated documentation      #
# files (the "Software"), to deal in the Software without             #
# restriction, including without limitation the rights to use, copy,  #
# modify, merge, publish, distribute, sublicense, and/or sell copies  #
# of the Software, and to permit persons to whom the Software is      #
# furnished to do so, subject to the following conditions:            #
#                                                                     #
# The above copyright notice and this permission notice shall be      #
# included in all copies of the Software, its documentation and       #
# marketing & publicity materials, and acknowledgment shall be given  #
# in the documentation, materials and software packages that this     #
# Software was used.                                                  #
#                                                                     #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,     #
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF  #
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND               #
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY    #
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF          #
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION  #
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.     #
#######################################################################

# load required libraries
require 'cgi'
require 'uri'
require 'time'
require 'net/http'
require 'rexml/document'

class String
  #
  # Escape XML-special characters in string.
  #
  def xml_escape
    str = gsub(/&/, '&amp;')
    str = str.gsub(/</, '&lt;')
    str = str.gsub(/>/, '&gt;')
    str = str.gsub(/"/, '&quot;')
    str
  end

  #
  # XML escape elements, including spaces, ?, and +
  #
  def uri_escape
    CGI::escape(self)
  end
end

class Time
  #
  # Convert from an ISO-8601-format string to a time.
  # 
  # Note: if there are more than one results in the string, this method
  # matches the first one.
  #
  def Time::from_iso8601(str)
    str.scan(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z/) do
      |yr, mo, dy, hr, mn, sc|
      return Time::mktime(yr, mo, dy, hr, mn, sc)
    end
  end

  #
  # Convert time to an ISO-8601-format string.
  #
  def to_iso8601
    strftime('%Y-%m-%dT%H:%M:%SZ')
  end
end

class Array
  #
  # Convert an array of posts (bookmarks) to an XBEL string.
  # 
  # Note: This method is significantly less taxing on Delicious than 
  # Rubilicious#to_xbel.
  #
  # Raises an exception on error.
  #
  # Example:
  #   results = r.recent             # grab all recent posts
  #   File::open('output.xbel', 'w') do |file|
  #     file.puts results.to_xbel    # save results to file
  #   end
  #
  def to_xbel(tag = nil)
    ret = [ "<?xml version='1.0' encoding='utf-8'?>",
            "<xbel version='1.0' added='#{Time::now.to_iso8601}'>",
            # "<xbel version='1.0'>",
            "  <title>#{@user}'s del.icio.us bookmarks</title>" ]
  
    # find all bookmarks in list with given tag and sort tag
    tags = find_all { |e| !tag || e['tags'].include?(tag) }.inject({}) do |tags, bm|
      if bm['tags'] && bm['tags'].size > 0
        bm['tags'] = bm['tags'] ? bm['tags'].split(' ').sort : []
        # TODO: alias support
        bm['tags'].each { |tag| tags[tag] ||= []; tags[tag] << bm }
      else 
        tags['uncategorized'] ||= []
        tags['uncategorized'] << bm
      end

      tags
    end
    
    # print the folders out in order
    tags.keys.sort.each do |tag|
      ary = tags[tag]
      ret <<  [ 
        "  <folder id='#{tag}' added='#{Time.now.to_iso8601}'>",
        # "  <folder id='#{tag}'>",
        "    <title>#{tag.capitalize}</title>",

        ary.sort { |a, b| a['description'] <=> b['description'] }.map do |bm|
          href, bm_id = bm['href'].uri_escape, "#{tag}-#{bm['hash']}", 
          time = bm['time'].to_iso8601
          title = bm['description'] ? bm['description'].xml_escape : ''
          desc = bm['extended'] ? bm['extended'].xml_escape : ''

          [ "    <bookmark href='#{href}' id='#{bm_id}' added='#{time}'>",
          # [ "    <bookmark href='#{href}' id='#{bm_id}'>",
            "      <title>#{title}</title>",
            "      <desc>#{desc}</desc>",
            "    </bookmark>" ,
          ].join("\n")
        end.join("\n"),

        '  </folder>',
      ].join("\n")
    end

    # attach closing tag and return string
    ret << '</xbel>'
    ret.join("\n")
  end
end

#
# Rubilicious - Delicious (http://del.icio.us/) bindings for Ruby.
#
# You'll need to create an account at Delicious (http://del.icio.us/) in
# order to use this API.
#
# Simple Examples:
#   # connect to delicious and get a list of your recent posts
#   r = Rubilicious.new('user', 'password')
#   r.recent.each do |post|
#     puts "#{post['desc']}: #{post['href']}"
#   end
#
#   # add a new link to delicious
#   r.add('http://pablotron.org/', 'Pablotron.org')
#
#   # save recent funny posts to an XBEL file
#   File::open('funny_links.xbel', 'w') do |file|
#     file.puts r.recent('funny').to_xbel
#   end
#
class Rubilicious
  attr_reader :user
  attr_accessor :use_proxy, :base_uri

  VERSION = '0.1.5'

  # list of environment variables to check for HTTP proxy
  PROXY_ENV_VARS = %w{RUBILICIOUS_HTTP_PROXY HTTP_PROXY http_proxy}

  #
  # get the HTTP proxy server and port from the environment
  # Returns [nil, nil] if a proxy is not set
  #
  # This method is private
  #
  def find_http_proxy
    ret = [nil, nil]

    # check the platform.  If we're running in windows then we need to 
    # check the registry
    if @use_proxy
      if RUBY_PLATFORM =~ /win32/i
        # Find a proxy in Windows by checking the registry.
        # this code shamelessly copied from Raggle :D

        require 'win32/registry'

        Win32::Registry::open(
          Win32::Registry::HKEY_CURRENT_USER,
          'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        ) do |reg|
          # check and see if proxy is enabled
          if reg.read('ProxyEnable')[1] != 0
            # get server, port, and no_proxy (overrides)
            server = reg.read('ProxyServer')[1]
            np = reg.read('ProxyOverride')[1]

            server =~ /^([^:]+):(.+)$/
            ret = [$1, $2]

            # don't bother with no_proxy support
            # ret['no_proxy'] = np.gsub(/;/, ',') if np && np.length > 0
          end
        end
      else
        # handle UNIX systems
        PROXY_ENV_VARS.each do |env_var|
          if ENV[env_var]
            # if we found a proxy, then parse it
            ret = ENV[env_var].sub(/^http:\/\/([^\/]+)\/?$/, '\1').split(':')
            ret[1] = ret[1].to_i if ret[1]
            break
          end
        end
        # $stderr.puts "DEBUG: http_proxy = #{ENV['http_proxy']}, ret = [#{ret.join(',')}]"
      end
    else 
      # proxy is disabled
      ret = [nil, nil]
    end

    # return host and port
    ret
  end

  #
  # Low-level HTTP GET.
  #
  # This method is private.
  #
  def http_get(url)
    # get proxy info
    proxy_host, proxy_port = find_http_proxy
    # $stderr.puts "DEBUG: proxy: host = #{proxy_host}, port = #{proxy_port}"

    # get host, port, and base URI for API queries
    uri = URI::parse(@base_uri)
    base = uri.request_uri

    # prepend base to url
    url = "#{base}/#{url}"

    # connect to delicious
    http = Net::HTTP.Proxy(proxy_host, proxy_port).new(uri.host, uri.port).start

    # get URL, check for error
    resp = http.get(url, @headers)
    raise "HTTP #{resp.code}: #{resp.message}" unless resp.code =~ /2\d{2}/

    # close HTTP connection, return response
    http.finish
    resp.body
  end

  #
  # Get url from del.icio.us, and optionally parse result and return as
  # an array of hashes as well.
  #
  # This method is private.
  #
  def get(url, elem = nil)
    # check last request time, if it was too recent, then wait
    sleep 1.0 if @last_request && (Time.now.to_i - @last_request) < 1
    @last_request = Time.now.to_i
    
    # get result and parse it
    ret = REXML::Document.new(http_get(url))
    
    # if we got something, then parse it
    if elem
      ary = []
      ret.root.elements.each("//#{elem}") do |e|
        hash = {}
        e.attributes.each { |key, val| hash[key] = val }
        ary << hash
      end
      ret = ary
    end

    # return result
    ret
  end

  # don't touch these :)
  private :get, :http_get, :find_http_proxy


  #
  # Connect to del.icio.us with username 'user' and password 'pass'.
  # 
  # Note: if the username or password is incorrect, Rubilicious will not
  # raise an exception until you make an actual call.
  #
  # Example:
  #   r = Rubilicious.new('pabs', 'password')
  #
  def initialize(user, pass)
    @user, @use_proxy = user, true
    @base_uri = ENV['RUBILICIOUS_BASE_URI'] || 'http://del.icio.us/api'
    @headers = {
      'Authorization'   => 'Basic ' << ["#{user}:#{pass}"].pack('m').strip,
      'User-Agent'      => "Rubilicious/#{Rubilicious::VERSION} Ruby/#{RUBY_VERSION}"
    }
  end

  #
  # Returns a list of dates with the number of posts at each date.  If a
  # tag is given, return a list of dates with the number of posts with
  # the specified tag at each date.
  #
  # Raises an exception on error.
  #
  # Examples:
  #   dates = r.dates
  #   puts "date,count"
  #   dates.keys.sort.each do |date| 
  #     puts "#{date},#{dates[date]}"
  #   end
  #
  #   # same as above, but only display 'politics' tags
  #   dates = r.dates('politics')
  #   puts "date,count",
  #        dates.map { |args| args.join(',') }.join("\n")
  #
  def dates(tag = nil)
    get('posts/dates?' << (tag ? "tag=#{tag}" : ''), 'date').inject({}) do  |ret, e|
      ret[e['date']] = e['count'].to_i
      ret
    end
  end

  #
  # Returns a hash of tags and the number of times they've been used.
  #
  # Raises an exception on error.
  #
  # Example:
  #   tags = r.tags
  #   puts tags.keys.sort.map { |tag| "#{tag},#{tags[tag]}" }.join("\n")
  #
  def tags
    get('tags/get?', 'tag').inject({}) do |ret, e|
      ret[e['tag']] = e['count'].to_i
      ret
    end
  end

  #
  # Returns an array of posts on a given date, filtered by tag. If no 
  # date is supplied, most recent date will be used.
  #
  # Raises an exception on error.
  #
  # Examples:
  #   # print out a list of recent links from oldest to newest.
  #   posts = r.posts
  #   posts.sort { |a, b| a['time'] <=> b['time'] }.each do |post|
  #     puts post['href']
  #   end
  # 
  #   # print out a list of link descriptions from the date '2004-09-22'
  #   posts = r.posts('2004-09-22')
  #   posts.sort { |a, b| a['description'] <=> b['description'] }
  #   posts.each { |post| puts post['description'] }
  #
  def posts(date = nil, tag = nil)
    args = [(date ? "dt=#{date}" : nil), (tag ? "tag=#{tag.uri_escape}" : nil)]
    get('posts/get?' << args.compact.join('&amp;'), 'post').map do |e|
      e['tags'] = e['tag'].split(' ')
      e.delete 'tag'
      e['time'] = Time::from_iso8601(e['time'])
      e
    end
  end

  #
  # Returns an array of the most recent posts, optionally filtered by tag.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # get the most recent links
  #   recent_links = r.recent.map { |post| post['href'] }
  #
  #   # get the 10 most recent 'music' links
  #   recent_links = r.recent('music', 10).map { |post| post['href'] }
  #
  def recent(tag = nil, count = nil)
    args = [(count ? "count=#{count}" : nil), (tag ? "tag=#{tag.uri_escape}" : nil)]
    get('posts/recent?' << args.compact.join('&amp;'), 'post').map do |e|
      e['tags'] = e['tag'].split(' ')
      e.delete 'tag'
      e['time'] = Time::from_iso8601(e['time'])
      e
    end
  end

  #
  # Post a link to delicious, along with an optional extended
  # description, tags (as a space-delimited list), and a timestamp.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # add a link to pablotron to delicious
  #   r.add('http://pablotron.org/', 
  #         'Pablotron.org : The most popular site on Internet?')
  #
  #   # add a link to paulduncan.org to delicious with an extended 
  #   # description
  #   r.add('http://paulduncan.org/', "Paul Duncan", "Damn he's smooth!")
  #
  #   # add a link with an extended description and some tags
  #   r.add('http://raggle.org/', 
  #         'Raggle', 'Console RSS Aggregator, written in Ruby.',
  #         'rss programming ruby console xml')
  #
  def add(url, desc, ext = '', tags = '', time = Time.now)
    raise "Missing URL" unless url
    raise "Missing Description" unless desc
    args = [
      ("url=#{url.uri_escape}"), ("description=#{desc.uri_escape}"),
      (ext ? "extended=#{ext.uri_escape}" : nil),
      (tags ? "tags=#{tags.uri_escape}" : nil), ("dt=#{time.to_iso8601}")
    ]
    get('posts/add?' << args.compact.join('&amp;'))
    nil
  end

  #
  # Delete a link from Delicious.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # delete a link to example.com from delicious
  #   r.delete('http://example.com/')
  #
  def delete(url)
    raise "Missing URL" unless url
    get('posts/delete?' << url.escape_uri)
    nil
  end

  #
  # Renames tags across all posts.
  #
  # Note: Delicious has currently disabled this feature, so it will not
  # work until they reenable it.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # rename tag "rss" to "xml"
  #   r.rename('rss', 'xml')
  #
  def rename(old, new)
    args = ["old=#{old.uri_escape}", "new=#{new.uri_escape}"]
    get('tags/rename?' << args.join('&amp;'))
    nil
  end

  #
  # Returns a array of inbox entries, optionally filtered by date.
  #
  # Raises an exception on error.
  # 
  # Example:
  #   # print a list of posts and who posted them
  #   r.inbox.each { |post| puts "#{post['user']},#{post['href']}" }
  #
  def inbox(date = nil)
    time_prefix = "#{date || Time.now.strftime('%Y-%m-%d')}T"
    ret = get('inbox/get?' << (date ? "dt=#{date}" : ''), 'post').map do |post|
      post['time'] = Time::from_iso8601("#{time_prefix}#{post['time']}Z")
      post
    end
    ret
  end

  #
  # Returns a hash of dates containing inbox entries.
  # 
  # Raises an exception on error.
  #
  # Example:
  #   # print out a list of the 10 busiest inbox dates
  #   dates = r.inbox_dates
  #   puts dates.keys.sort { |a, b| dates[b] <=> dates[a] }.slice(0, 10)
  #
  def inbox_dates
    get('inbox/dates?', 'date').inject({}) do  |ret, e|
      ret[e['date']] = e['count'].to_i
      ret
    end
  end

  #
  # Returns a hash of your subscriptions.
  # 
  # Raises an exception on error.
  #
  # Example:
  #   # print out a list of subscriptions
  #   subs = r.subs
  #   puts "user:tags"
  #   subs.keys.sort.each do |sub| 
  #     puts "#{sub}:#{subs[sub].join(' ')}"
  #   end
  #
  def subs
    get('inbox/subs?', 'sub').inject({}) do |ret, e|
      ret[e['user']] = [] unless ret[e['user']]
      ret[e['user']] += e['tag'].split(' ')
      ret
    end
  end

  #
  # Add a subscription, optionally to a specific tag.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # subscribe to 'humor' links from solarce
  #   r.sub('solarce', 'humor')
  #
  def sub(user, tag = nil)
    raise "Missing user" unless user
    args = ["user=#{user.uri_escape}", (tag ? "tag=#{tag.uri_escape}" : nil)]
    get('inbox/sub?' << args.compact.join('&amp;'), 'post')
    nil
  end

  #
  # Removes a subscription, optionally only a specific tag.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # unsubscribe from all links from giblet
  #   r.unsub('giblet')
  #
  def unsub(user, tag = nil)
    raise "Missing user" unless user
    args = ["user=#{user}", (tag ? "tag=#{tag}" : nil)]
    get('inbox/unsub?' << args.compact.join('&amp;'))
    nil
  end

  #
  # Return the last update time.
  #
  # Note: this method should be used before calling methods like .posts
  # or .all to conserve on bandwidth.
  # 
  # Example:
  #  t = r.update  #=> "Fri Mar 11 02:45:51 EST 2005"
  #
  def update
    Time::xmlschema(get('posts/update', 'update')[0]['time'])
  end

  #
  # Return an array of all your posts ever, optionally filtered by tag.
  #
  #
  # WARNING: This method can generate a large request to del.icio.us,
  # and should be used sparingly, and at your own risk.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # save all 'art' posts to file "art_posts.txt"
  #   art_posts = r.all('art')
  #   File::open('art_posts.txt', 'w') do |file|
  #     file.puts art_posts.sort do |a, b| 
  #       a['time'] <=> b['time'] 
  #     end.map { |post| post['href'] }
  #   end
  #
  def all(tag = nil)
    args = [(tag ? "tag=#{tag.uri_escape}" : nil)]
    get('posts/all?' << args.compact.join('&amp;'), 'tag')
  end

  #
  # Return an XBEL string of all your posts, optionally filtered by tag.
  #
  # WARNING: This method can generate a large number of requests to 
  # del.icio.us, and could be construed as abuse.  Use sparingly, and at
  # your own risk.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # save all posts ever in XBEL format to file "delicious.xbel"
  #   File::open('delicious.xbel', 'w') do |file|
  #     file.puts r.to_xbel
  #   end
  #
  def to_xbel(tag = nil)
    ret = [ "<?xml version='1.0' encoding='utf-8'?>",
            "<xbel version='1.0' added='#{Time::now.to_iso8601}'>",
            # "<xbel version='1.0'>",
            "  <title>#{@user}'s del.icio.us bookmarks</title>" ]
  
    tags = all(tag).inject({}) do |tags, bm|
      if bm['tags'] && bm['tags'].size > 0
        bm['tags'].sort!
        # TODO: alias support
        bm['tags'].each { |tag| tags[tag] ||= []; tags[tag] << bm }
      else 
        tags['unsorted'] ||= []
        tags['unsorted'] << bm
      end

      tags
    end
    
    tags.keys.sort.each do |tag|
      ary = tags[tag]
      ret <<  [ 
        "  <folder id='#{tag}' added='#{Time.now.to_iso8601}'>",
        # "  <folder id='#{tag}'>",
        "    <title>#{tag.capitalize}</title>",

        ary.sort { |a, b| a['description'] <=> b['description'] }.map do |bm|
          href, bm_id = bm['href'].uri_escape, "#{tag}-#{bm['hash']}", 
          time = bm['time'].to_iso8601
          title = bm['description'] ? bm['description'].xml_escape : ''
          desc = bm['extended'] ? bm['extended'].xml_escape : ''

          [ "    <bookmark href='#{href}' id='#{bm_id}' added='#{time}'>",
          # [ "    <bookmark href='#{href}' id='#{bm_id}'>",
            "      <title>#{title}</title>",
            "      <desc>#{desc}</desc>",
            "    </bookmark>" ,
          ].join("\n")
        end.join("\n"),

        '  </folder>',
      ].join("\n")
    end

    ret << '</xbel>'
    ret.join("\n")
  end

  #
  # Return all of a user's posts, optionally filtered by tag.
  #
  # WARNING: This method can generate a large number of requests to 
  # del.icio.us, and could be construed as abuse.  Use sparingly, and at
  # your own risk.
  #
  # Raises an exception on error.
  #
  # Example:
  #   # save all posts every by 'delineator' to XBEL format to file
  #   # "delineator.xbel"
  #   File::open('delineator.xbel', 'w') do |file|
  #     file.puts r.user_posts('delineator').to_xbel
  #   end
  #
  def user_posts(user, tag = nil)
    was_subscribed = true
    ret = []

    # unless we already subscribed, subscribe to user
    unless subs.keys.include?(user)
      sub(user)
      was_subscribed = false
    end
    
    # grab list of user's posts
    inbox_dates.keys.each do |date|
      ret += inbox(date).find_all do |post| 
        post['user'] == user && (tag == nil || post['tags'].include?(tag))
      end
    end

    # unsubscribe from user unless we were already subscribed
    unsub(user) unless was_subscribed

    # return list of user's posts
    ret
  end

  # convenience aliases
  alias :rename_tag :rename
  alias :subscriptions :subs
  alias :subscribe :sub
  alias :unsubscribe :unsub
  alias :all_posts :all
end
