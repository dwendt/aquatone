require 'ipaddr'

module Aquatone
  module IPRange

    # Attempt to parse CIDR and nmap formats. If the input is invalid,
    # the resulting array will likely be empty. Check this when used.
    def self.parse(value)
      result = []

      # Allow several ranges to be comma-delimited, ignore whitespace
      value.gsub!(" ","")
      ranges = value.split(",")

      ranges.each do |r|
        # If it's a CIDR, just add it to our array.
        if r.include?("/")
          begin
            ipobj = IPAddr.new(r)
            result << (ipobj.to_range)
          rescue IPAddr::Error
            # If it's not a valid CIDR but it had a '/', we've got invalid format.
            return []
          end
        else
          # Not a CIDR? handle wildcards
          r.gsub!("*","0-255")

          # Go octet by octet converting ranges to arrays of possible values
          final = [[],[],[],[]]
          octets = r.split(".")

          # Maybe we should support things like "10" as "10.0.0.0/8", but not yet.
          if octets.length != 4 
            return []
          end

          octets.each_with_index do |o,i|
            if o.include? "-"
              tmp = o.split("-")

              # If the user provided an invalid format, bail out. 
              return [] if tmp.length < 2

              # Get a range, then an array of numbers, and add it to that octet's 
              # final set of possible values.
              final[i].concat( ( (tmp[0].to_i)..(tmp[1].to_i) ).to_a )
            else
              # Make sure you didn't type ".." on accident.
              return [] if o.length < 1

              final[i] << o
            end
          end

          # Add all possible combinations to our result.
          final[0].each do |a|
            final[1].each do |b|
              final[2].each do |c|
                final[3].each do |d|
                  result << "#{a}.#{b}.#{c}.#{d}"
                end
              end
            end
          end # combinations
        end # else for non-cidr IPrange
      end # each over comma-separated values

      return result
    end # self.parse

    # The array elements can be a range of IPAddr or a string.
    def self.contains(arr,ip)
      return true if arr.include? ip

      arr.each do |v|
        if v.include? ip
          return true
        end
      end

      return false
    end

  end
end
