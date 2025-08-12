require 'openssl'

HASH_FUNCTIONS = {
  md5: 'MD5',
  sha1: 'SHA1',
  sha224: 'SHA224',
  sha256: 'SHA256',
  sha384: 'SHA384',
  sha512: 'SHA512',
  sha512_224: 'SHA512-224',
  sha512_256: 'SHA512-256',
  sha3_224: 'SHA3-224',
  sha3_256: 'SHA3-256',
  sha3_384: 'SHA3-384',
  sha3_512: 'SHA3-512',
  blake2s256: 'BLAKE2s256',
  blake2b512: 'BLAKE2b512'
}.freeze

HASH_TYPE = :sha256

#
# Modified Integer class
#
class Integer
  #
  # Convert Integer of length 8 bytes to bytes String in little endian.
  #
  # @return [String] Bytes String in little endian.
  #
  def to_bytestring
    [self].pack('Q<')
  end
end

#
# Modified String class
#
class String
  #
  # XOR two strings
  #
  # @param [String] other Other string to XOR with.
  #
  # @return [String] XOR result.
  #
  def ^(other)
    # Modified from https://stackoverflow.com/a/6099613
    b1 = unpack('Q*')
    b2 = other.unpack('Q*')
    longest = [b1.length, b2.length].max
    b1 = ([0] * (longest - b1.length)) + b1
    b2 = ([0] * (longest - b2.length)) + b2
    b1.zip(b2).map { |a, b| a ^ b }.pack('Q*')
  end
end

#
# Concatenate all the arguments and hash the result.
# Note that the hash function used can be modified
# in the global parameter `HASH_TYPE``.
#
# @param [Any] *args Arguments to concatenate.
#
# @return [String] The hashed string.
#
def hash_func(*args)
  t = ''

  args.each do |arg|
    t += if arg.instance_of? Integer
           arg.to_bytestring
         else
           arg
         end
  end
  OpenSSL::Digest.new(HASH_FUNCTIONS[HASH_TYPE]).digest(t)
end

#
# First step of the algorithm. Fill up a buffer with
# pseudorandom bytes derived from the password and salt
# by computing repeatedly the hash function on a combination
# of the password and the previous hash.
#
# @param [Array] buf An array of hashes as bytes.
# @param [Integer] cnt Used in a security proof (read the paper).
# @param [Integer] space_cost The size of the buffer.
#
# @return [Integer] Updates the buffer and counter, and returns the counter
#
def expand(buf, cnt, space_cost)
  (1...space_cost).each do |s|
    buf << hash_func(cnt, buf[s - 1])
    cnt += 1
  end
  cnt
end

#
# Second step of the algorithm. Mix `time_cost` number
# of times the pseudorandom bytes in the buffer. At each
# step in the for loop, update the nth block to be
# the hash of the n-1th block, the nth block, and `delta`
# other blocks chosen at random from the buffer `buf`.
#
# @param [Array] buf An array of hashes as bytes.
# @param [Integer] cnt Used in a security proof (read the paper).
# @param [Integer] delta Number of random blocks to mix with.
# @param [String] salt A user defined random value for security.
# @param [Integer] space_cost The size of the buffer.
# @param [Integer] time_cost Number of rounds to mix.
#
# @return [nil] Updates the buffer and counter, but does not return anything.
#
def mix(buf, cnt, delta, salt, space_cost, time_cost)
  (0...time_cost).each do |t|
    (0...space_cost).each do |s|
      buf[s] = hash_func(cnt, buf[s - 1], buf[s])
      cnt += 1
      (0...delta).each do |i|
        idx_block = hash_func(t, s, i)
        # Converts byte array to integer (little endian), see https://stackoverflow.com/a/68855488
        other = hash_func(cnt, salt, idx_block).bytes.reverse.inject(0) { |m, b| (m << 8) + b } % space_cost
        cnt += 1
        buf[s] = hash_func(cnt, buf[s], buf[other])
        cnt += 1
      end
    end
  end
end

#
# Final step. Return the last value in the buffer.
#
# @param [Array] buf An array of hashes as bytes.
#
# @return [String] Last value of the buffer as bytes.
#
def extract(buf)
  buf[-1]
end

#
# Main function that collects all the substeps. As
# previously mentioned, first expand, then mix, and
# finally extract. Note the result is returned as bytes String,
# for a more friendly function with default values
# that returns a hex string, see the function `balloon_hash`.
#
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
# @param [Integer] space_cost The size of the buffer.
# @param [Integer] time_cost Number of rounds to mix.
# @param [Integer] delta Number of random blocks to mix with. Defaults to 3.
#
# @return [String] A series of bytes, the hash.
#
def balloon(password, salt, space_cost, time_cost, delta = 3)
  buf = [hash_func(0, password, salt)]
  cnt = 1

  cnt = expand(buf, cnt, space_cost)
  mix(buf, cnt, delta, salt, space_cost, time_cost)
  extract(buf)
end

#
# A more friendly client function that just takes
# a password and a salt and outputs the hash as a hex string.
#
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
#
# @return [String] The hash as hex.
#
def balloon_hash(password, salt)
  delta = 4
  time_cost = 20
  space_cost = 16
  balloon(password, salt, space_cost, time_cost, delta).unpack1('H*')
end

#
# M-core variant of the Balloon hashing algorithm. Note the result
# is returned as bytes, for a more friendly function with default
# values that returns a hex string, see the function `balloon_m_hash`.
#
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
# @param [Integer] space_cost The size of the buffer.
# @param [Integer] time_cost Number of rounds to mix.
# @param [Integer] parallel_cost Number of concurrent instances.
# @param [Integer] delta Number of random blocks to mix with. Defaults to 3.
#
# @return [String] A series of bytes, the hash.
#
def balloon_m(password, salt, space_cost, time_cost, parallel_cost, delta = 3)
  threads = (0...parallel_cost).map do |p|
    Thread.new do
      parallel_salt = "#{salt}#{(p + 1).to_bytestring}"
      balloon(password, parallel_salt, space_cost, time_cost, delta)
    end
  end
  output = threads.reduce('') do |current, thread|
    current ^ thread.value
  end
  hash_func(password, salt, output)
end

#
# A more friendly client function that just takes
# a password and a salt and outputs the hash as a hex string.
# This uses the M-core variant of the Balloon hashing algorithm.
#
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
#
# @return [String] The hash as hex.
#
def balloon_m_hash(password, salt)
  delta = 4
  time_cost = 20
  space_cost = 16
  parallel_cost = 4
  balloon_m(password, salt, space_cost, time_cost, parallel_cost, delta).unpack1('H*')
end

#
# Verify that hash matches password when hashed with salt, space_cost,
# time_cost, and delta.
#
# @param [String] The hash to check against.
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
# @param [Integer] space_cost The size of the buffer.
# @param [Integer] time_cost Number of rounds to mix.
# @param [Integer] delta Number of random blocks to mix with. Defaults to 3.
#
# @return [TrueClass] True if password matches hash, otherwise False.
#
def verify(hash, password, salt, space_cost, time_cost, delta = 3)
  OpenSSL.secure_compare(balloon(password, salt, space_cost, time_cost, delta).unpack1('H*'), hash)
end

#
# Verify that hash matches password when hashed with salt, space_cost,
# time_cost, parallel_cost, and delta.
# This uses the M-core variant of the Balloon hashing algorithm.
#
# @param [String] The hash to check against.
# @param [String] password The main string to hash.
# @param [String] salt A user defined random value for security.
# @param [Integer] space_cost The size of the buffer.
# @param [Integer] time_cost Number of rounds to mix.
# @param [Integer] parallel_cost Number of concurrent instances.
# @param [Integer] delta Number of random blocks to mix with. Defaults to 3.
#
# @return [TrueClass] True if password matches hash, otherwise False.
#
def verify_m(hash, password, salt, space_cost, time_cost, parallel_cost, delta = 3)
  OpenSSL.secure_compare(
    balloon_m(password, salt, space_cost, time_cost, parallel_cost, delta).unpack1('H*'), hash
  )
end
