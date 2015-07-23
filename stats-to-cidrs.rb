#!/usr/bin/env ruby

# This helper scripts translates stdin in RIR Statistics Exchange Format [1]
# or NRO Extended Stats Format [2] into stdout in "dotted-quad/masklen" CIDR
# format (one CIDR block per line). It processes only assigned/allocated IPv4
# address ranges and produces one or more CIDR blocks for each range.
#
# 1: ftp://ftp.ripe.net/ripe/stats/RIR-Statistics-Exchange-Format.txt
# 2: https://www.arin.net/knowledge/statistics/nro_extended_stats_format.pdf

# "gem install ipaddress" or "yum install rubygem-ipaddress"
require 'ipaddress'

DENOMINATORS =
  { 2**24 => 24, 2**23 => 23, 2**22 => 22, 2**21 => 21, 2**20 => 20,
    2**19 => 19, 2**18 => 18, 2**17 => 17, 2**16 => 16, 2**15 => 15,
    2**14 => 14, 2**13 => 13, 2**12 => 12, 2**11 => 11, 2**10 => 10,
    2**9 => 9, 2**8 => 8, 2**7 => 7, 2**6 => 6, 2**5 => 5, 2**4 => 4,
    2**3 => 3 }.freeze

def max_pow2_denominating(x)
  DENOMINATORS.each do |pow, index|
    return index if x % pow == 0
  end
  raise(ArgumentError)
end

def max_pow2_not_greater(x)
  Integer(Math.log2(x))
end

re = /\|ipv4\|([\d\.]+)\|(\d+)\|\d+\|(?:allocated|assigned)/
ARGF.each_line do |line|
  next if (match = re.match(line)).nil?
  start = IPAddress::IPv4.new(match[1]).u32
  count = Integer(match[2])
  raise(ArgumentError, '/8 is the largest allowed prefix') if count > 2**24
  while count > 0
    idx2 = [max_pow2_denominating(start), max_pow2_not_greater(count)].min
    raise(ArgumentError, '/29 is the smallest allowed prefix') if idx2 < 3
    puts(IPAddress::IPv4.parse_u32(start, 32 - idx2).to_string)
    start += 2**idx2
    count -= 2**idx2
  end
end
