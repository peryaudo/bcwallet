#!/usr/bin/env ruby

#
# bcwallet.rb: Educational Bitcoin Client 
#
# This is a tiny Bitcoin client implementation which uses
# Simplified Payment Verification (SPV).
#

# WARNING: This client is for technical education,
# skips a lot of validations, and may have critical bugs.
#
# USE OF THE CLIENT IN MAIN NETWORK MAY CAUSE YOUR COINS LOST.
#
# DO NOT SET THIS VALUE "false".
#
IS_TESTNET = true

# Remote host to use: It is recommended to use this client with a local client.
# Install Bitcoin-Qt and then launch with -testnet option to connect Testnet.
HOST = 'localhost'

# This software is licensed under the MIT license.
#
# The MIT License (MIT)
# 
# Copyright (c) 2014 peryaudo
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

require 'openssl'
require 'socket'

#
# A class which manages both public key and private key in OpenSSL's ECDSA.
#
class Key
  public

  #
  # Bitcoin mainly uses SHA-256(SHA-256(plain)) as a cryptographic hash function
  # when a hash is needed.
  #
  def self.hash256(plain)
    return OpenSSL::Digest::SHA256.digest(OpenSSL::Digest::SHA256.digest(plain))
  end

  #
  # RIPEMD-160(SHA-256(plain)) is used when a shorter hash is preferable.
  #
  def self.hash160(plain)
    return OpenSSL::Digest::RIPEMD160.digest(OpenSSL::Digest::SHA256.digest(plain))
  end

  BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

  #
  # Modified version of Base58 is used in Bitcoin to convert binaries into human-typable strings.
  #
  def self.encode_base58(plain)
    # plain is big endian

    num = plain.unpack("H*").first.hex

    res = ''

    while num > 0
      res += BASE58[num % 58]
      num /= 58
    end

    # restore leading zeroes
    plain.each_byte do |c|
      break if c != 0
      res += BASE58[0]
    end

    return res.reverse
  end

  def self.decode_base58(encoded)
    num = 0
    encoded.each_char do |c|
      num *= 58
      num += BASE58.index(c)
    end

    res = num.to_s(16)

    if res % 2 == 1 then
      res = '0' + res
    end

    # restore leading zeroes
    encoded.each_char do |c|
      break if c != BASE58[0]
      res += '00'
    end

    return [res].pack('H*')
  end

  #
  # Base58 with the type of data and the checksum is called Base58Check in Bitcoin protocol.
  # It is used as a Bitcoin address, human-readable private key, and so on.
  #
  def self.encode_base58check(type, plain)
    leading_bytes = {
      :main    => { :public_key => 0,   :private_key => 128 },
      :testnet => { :public_key => 111, :private_key => 239 }
    }

    leading_byte = [leading_bytes[IS_TESTNET ? :testnet : :main][type]].pack('C')

    data = leading_byte + plain
    checksum = Key.hash256(data)[0, 4]

    return Key.encode_base58(data + checksum)
  end

  def self.decode_base58check(encoded)
    decoded = Key.decode_base58(encoded)

    raise "invalid base58 checksum" if Key.hash256(decoded[0, decoded.length - 4])[0, 4] != decoded[-4, 4]

    types = {
      :main    => { 0   => :public_key, 128 => :private_key },
      :testnet => { 111 => :public_key, 239 => :private_key }
    }

    type = types[IS_TESTNET ? :testnet : :main][decoded[0].unpack('C').first]

    return {:type => type, :data => decoded[1, decoded.length - 5]}
  end

  #
  # Initialize with ASCII-encoded DER format string (nil to generate a new key)
  #
  def initialize(der = nil)
    if der then
      @key = OpenSSL::PKey::EC.new([der].pack('H*'))
    else
      @key = OpenSSL::PKey::EC.new('secp256k1')
      @key = @key.generate_key
    end

    @key.check_key
  end

  #
  # Sign the data with the key.
  #
  def sign(data)
    return @key.dsa_sign_asn1(data)
  end

  #
  # Convert public key to Bitcoin address.
  #
  def to_address_s
    return Key.encode_base58check(:public_key, Key.hash160(@key.public_key.to_bn.to_s(2)))
  end

  # 
  # Convert the private key to Bitcoin private key import format.
  #
  def to_private_key_s
    return Key.encode_base58check(:private_key, @key.private_key.to_s(2))
  end

  #
  # Convert the key pair into ASCII-encoded DER format string.
  #
  def to_der_hex_s
    return @key.to_der.unpack('H*').first
  end

  def to_public_key
    return @key.public_key.to_bn.to_s(2)
  end

  def to_public_key_hash
    return Key.hash160(@key.public_key.to_bn.to_s(2))
  end
end

#
# A class which generates Bloom filter.
# Bloom filter is a data structure used in Bitcoin to filter transactions for SPV clients.
# It enables you to quickly test an element is included in a set,
# but may have false positives. (probabilistic data structure)
#
class BloomFilter
  public
  #
  # len = length of bloom filter
  # hash_funcs = number of hash functions to use 
  # tweak = a random number
  #
  def initialize(len, hash_funcs, tweak)
    @filter = Array.new(len, 0)
    @hash_funcs = hash_funcs
    @tweak = tweak
  end

  #
  # See an array as a huge little endian integer, and fill idx-th bit
  #
  def set_bit(idx)
    @filter[idx >> 3] |= (1 << (7 & idx))
  end

  def rotate_left_32(x, r)
    return ((x << r) | (x >> (32 - r))) & 0xffffffff
  end

  #
  # The hash functions is called MurmurHash3 (32-bit).
  # Reference implementation is somewhat tricky one, 
  # so I recommend you to read bitcoinj's one if you want to know the detail.
  #
  def hash(seed, data)
    mask = 0xffffffff

    h1 = seed & mask
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    data.unpack('V*').each do |k1|
      k1 = (k1 * c1) & mask
      k1 = rotate_left_32(k1, 15)
      k1 = (k1 * c2) & mask

      h1 = h1 ^ k1
      h1 = rotate_left_32(h1, 13)
      h1 = (h1 * 5 + 0xe6546b64) & mask
    end

    padded_remaining_bytes = data[(data.length & (mask ^ 3))..-1] + "\0" * (4 - (data.length & 3))

    k1 = padded_remaining_bytes.unpack('V').first
    k1 = (k1 * c1) & mask
    k1 = rotate_left_32(k1, 15)
    k1 = (k1 * c2) & mask
    h1 = h1 ^ k1

    h1 = (h1 ^ data.length) & mask
    h1 = h1 ^ (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & mask
    h1 = h1 ^ (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & mask
    h1 = h1 ^ (h1 >> 16)

    return h1
  end

  #
  # Insert the data into the Bloom filter
  #
  def insert(data)
    @hash_funcs.times do |i|
      set_bit(hash(i * 0xfba4c795 + @tweak, data) % (@filter.length * 8))
    end
  end

  def to_s
    res = ''
    @filter.each do |byte|
      res += [byte].pack('C')
    end
    return res
  end
end

#
# The network class. It should be separated into two or three classes
# to manage multiple connections in real implementation.
# However, since this is a extremely simplified implementation, they are integrated into this class.
#
class Network
  public

  attr_reader :status, :data

  # 
  # keys = { name => ECDSA key objects }
  #
  def initialize(keys, data_file_name)
    @keys = keys
    @data_file_name = data_file_name

    keys_hash = Key.hash256(keys.collect { |key, _| key }.sort.join)

    @data = { :blocks => {}, :txs => {}, :last_height => 0, :keys_hash => keys_hash }
    @is_sync_finished = true

    load_data

    if @data[:keys_hash] != keys_hash then
      # new keys are added since the last synchronization
      @data = { :blocks => {}, :txs => {}, :last_height => 0, :keys_hash => keys_hash }
    end

    # These hashes are genesis blocks'.
    @last_hash = { :timestamp => 0,
                   :hash => [IS_TESTNET ?
                     '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943' :
                     '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'].pack('H*').reverse }

    @data[:blocks].each do |hash, block|
      if block[:timestamp] > @last_hash[:timestamp] then
        @last_hash = { :timestamp => block[:timestamp], :hash => hash }
      end
    end

    @requested_data = 0
    @received_data = 0
  end

  #
  # Synchronize the block chain.
  # It creates a new thread and returns immediately.
  # To know whether the thread was finished, use Network#sync_finished?
  #
  def sync
    Thread.abort_on_exception = true
    @is_sync_finished = false
    t = Thread.new do

      unless @socket then
        @status = 'connection establishing ... '

        @socket = TCPSocket.open(HOST, IS_TESTNET ? 18333 : 8333)

        send_version
      end

      if @created_transaction then
        @status = 'announcing transaction ... '

        send_transaction_inv
      end

      loop do
        break if dispatch_message
      end

      @is_sync_finished = true
    end
    t.run
  end

  def sync_finished?
    return @is_sync_finished
  end

  # 
  # Send coins to the address.
  # from_key = Key object which the client sends coins from
  # to_addr  = Receiving address (string)
  # transaction_fee = Transaction fee which miners receive
  #
  def send(from_key, to_addr, amount, transaction_fee = 0)
    # The process of announcing a created transaction is as follows: 
    #   Generate tx message and get its hash, and send inv message with the hash to the remote host.
    #   Then the remote host will send getdata, so you can now actually send tx message.

    to_addr_decoded = Key.decode_base58check(to_addr)

    raise "invalid address" if to_addr_decoded[:type] != :public_key

    public_key_hash = from_key.to_public_key_hash

    set_spent_for_tx_outs

    # In a real SPV client, we should walk along merkle trees to validate the transaction.
    # It will be implemented to this client soon.
    total_satoshis = 0
    tx_in = []
    @data[:txs].each do |tx_hash, tx|
      break if total_satoshis >= amount

      matched = nil
      pk_script = nil

      tx[:tx_out].each_with_index do |tx_out, index|
        next if tx_out[:spent]

        if extract_public_key_hash_from_script(tx_out[:pk_script]) == public_key_hash then
          total_satoshis += tx_out[:value]
          matched = index
          pk_script = tx_out[:pk_script]
          break
        end
      end

      if matched then
        tx_in.push({ :previous_output => { :hash => tx[:hash], :index => matched },
                     :signature_script => '',
                     :sequence => ((1 << 32) - 1),

                     # not included in serialized data, but used to make signature
                     :pk_script => pk_script })
      end
    end

    payback = total_satoshis - amount - transaction_fee

    raise "you don't have enough balance to pay" unless payback >= 0

    # pk_script field is constructed in Bitcoin's scripting system
    #    https://en.bitcoin.it/wiki/Script
    #
    prefix = ['76a914'].pack('H*') # OP_DUP OP_HASH160 [length of the address]
    postfix = ['88ac'].pack('H*')  # OP_EQUALVERIFY OP_CHECKSIG
    
    tx_out = [{ :value => amount,  :pk_script => (prefix + to_addr_decoded[:data] + postfix) },
              { :value => payback, :pk_script => (prefix + public_key_hash + postfix) }]

    @created_transaction = {
      :command => :tx,

      :version => 1,
      :tx_in => tx_in,
      :tx_out => tx_out,
      :lock_time => 0
    }

    # We have generated all data without signatures, so we're now going to generate signatures.
    # However, it is very complicated one.
 
    signatures = []

    tx_in.each_with_index do |tx_in_elm, i|
      duplicated = @created_transaction.dup
      duplicated[:tx_in] = duplicated[:tx_in].dup
      duplicated[:tx_in][i] = duplicated[:tx_in][i].dup

      # To generate signature, you need hash256 of the whole transaction in special form.
      # The transaction in that form is different from usual one,
      # because the signature_script field in the tx_in to sign is
      # replaced with pk_script in previous tx_out,
      # and other tx_ins' signature_scripts are empty.
      # (make sure that var_int for the length is also set to zero)
      #
      # For better understanding, see: 
      #   https://en.bitcoin.it/w/images/en/7/70/Bitcoin_OpCheckSig_InDetail.png
      #

      duplicated[:tx_in][i][:signature_script] = tx_in_elm[:pk_script]

      serialize_message(duplicated)

      # hash256 includes type code field (see the figure in the URL above)
      verified_str = Key.hash256(@payload + [1].pack('V'))

      signatures.push from_key.sign(verified_str)
    end

    # see the figure in the URL above
    signatures.each_with_index do |signature, i|
      @created_transaction[:tx_in][i][:signature_script] =
        [signature.length + 1].pack('C') + signature + [1].pack('C') +
        [from_key.to_public_key.length].pack('C') + from_key.to_public_key
    end

    @status = ''
  end

  #
  # Get balance for the keys
  #
  def get_balance
    balance = {}
    @keys.each do |addr, _|
      balance[addr] = 0
    end

    set_spent_for_tx_outs

    @data[:txs].each do |tx_hash, tx|
      @keys.each do |addr, key|
        public_key_hash = key.to_public_key_hash

        tx[:tx_out].each do |tx_out|
          # The tx_out was already spent
          next if tx_out[:spent]

          if extract_public_key_hash_from_script(tx_out[:pk_script]) == public_key_hash then
            balance[addr] += tx_out[:value]
          end
        end
      end
    end

    return balance
  end

  private

  PROTOCOL_VERSION = 70001

  def load_data
    return unless File.exists?(@data_file_name)

    open(@data_file_name, 'rb') do |file|
      @data = Marshal.restore(file)
    end
  end

  def save_data
    open(@data_file_name, 'wb') do |file|
      Marshal.dump @data, file
    end
  end

  # 
  # Read a message and parse it using message definitions.
  #
  def read_message
    magic = @socket.read(4).unpack('H*').first
    raise 'invalid magic received' if magic != (IS_TESTNET ? '0b110907' : 'f9beb4d9')

    command  = @socket.read(12).unpack('A12').first.to_sym
    length   = @socket.read(4).unpack('V').first
    checksum = @socket.read(4)

    @r_payload = @socket.read(length)

    raise 'incorrect checksum' if Key.hash256(@r_payload)[0, 4] != checksum

    raise "unknown message #{command}" unless message_defs.has_key?(command)

    res = { :command => command }

    message_defs[command].each do |message_def|
      res[message_def.first] = message_def.last.call(:read)
    end

    return res
  end

  #
  # Serialize a message using message definitions.
  #
  def serialize_message(message)
    @payload = ''
    message_defs[message[:command]].each do |message_def|
      message_def.last.call(:write, message[message_def.first]) unless message_def.first == :hash
    end
  end

  #
  # Actually send a message to the remote host.
  #
  def write_message(message)
    # Create payload
    serialize_message(message)

    # 4bytes: magic
    raw_message = [IS_TESTNET ? '0b110907' : 'f9beb4d9'].pack('H*')

    # 12bytes: command (padded with zeroes)
    raw_message += [message[:command].to_s].pack('a12')

    # 4bytes: length of payload
    raw_message += [@payload.length].pack('V')

    # 4bytes: checksum
    raw_message += Key.hash256(@payload)[0, 4]

    # payload
    raw_message += @payload

    @socket.write raw_message
    @socket.flush
  end

  #
  # Serializer & deserializer methods
  #

  def read_bytes(len)
    res = @r_payload[0, len]
    @r_payload = @r_payload[len..-1]
    return res
  end

  def write_bytes(val)
    @payload += val
  end

  def fixed_integer(templ, len, rw, val = nil)
    case rw
    when :read 
      res = read_bytes(len).unpack(templ).first
      return res
    when :write
      write_bytes([val].pack(templ))
    end
  end

  def uint8(rw, val = nil)
    return fixed_integer('C', 1, rw, val)
  end

  def uint16(rw, val = nil)
    return fixed_integer('v', 2, rw, val)
  end

  def uint32(rw, val = nil)
    return fixed_integer('V', 4, rw, val)
  end

  def uint64(rw, val = nil)
    return fixed_integer('Q', 8, rw, val)
  end

  def integer(rw, val = nil)
    case rw
    when :read
      top = uint8(:read)

      if top < 0xfd then
        return top
      elsif top == 0xfd then
        return uint16(:read)
      elsif top == 0xfe then
        return uint32(:read)
      elsif top == 0xff then
        return uint64(:read)
      end

    when :write
      if val < 0xfd then
        uint8(:write, val)
      elsif val <= 0xffff then
        uint8(:write, 0xfd)
        uint16(:write, val)
      elsif val <= 0xffffffff then
        uint8(:write, 0xfe)
        uint32(:write, val)
      else
        uint8(:write, 0xff)
        uint64(:write, val)
      end
    end
  end

  def string(rw, val = nil)
    case rw
    when :read
      len = integer(:read)
      return read_bytes(len)
    when :write
      integer(:write, val.length)
      write_bytes(val)
      return val
    end
  end

  def net_addr(rw, val = nil)
    # accurate serializing is not necessary
    case rw
    when :read
      read_bytes(26)
      return {}
    when :write
      write_bytes([0, '00000000000000000000FFFF', '00000000', 8333].pack('QH*H*v'))
      return val
    end
  end

  def relay_flag(rw, val = nil)
    case rw
    when :read
      if @r_payload.length > 0 then
        return uint8(:read)
      else
        return true
      end
    when :write
      unless val then
        uint8(:write, 0)
      end
      return val
    end
  end

  def array(elm, rw, val = nil)
    case rw
    when :read
      count = integer(:read)
      res = []
      count.times do
        res.push elm.call(:read)
      end
      return res
    when :write
      integer(:write, val.length)
      val.each do |v|
        elm.call(:write, v)
      end
      return val
    end
  end
  def hash256(rw, val = nil)
    case rw
    when :read
      res = read_bytes(32)
      return res
    when :write
      write_bytes(val)
      return val
    end
  end

  def inv_vect(rw, val = {})
    return { :type => uint32(rw, val[:type]), :hash => hash256(rw, val[:hash]) }
  end

  def block_hash(rw, val = {})
    case rw
    when :read
      return Key.hash256(@r_payload[0, 80])
    end
  end

  def tx_hash(rw, val = {})
    case rw
    when :read
      return Key.hash256(@r_payload)
    end
  end

  def outpoint(rw, val = {})
    return { :hash => hash256(rw, val[:hash]), :index => uint32(rw, val[:index]) }
  end

  def tx_in(rw, val = {})
    return { :previous_output  => outpoint(rw, val[:previous_output]),
             :signature_script => string(rw, val[:signature_script]),
             :sequence         => uint32(rw, val[:sequence]) }
  end

  def tx_out(rw, val = {})
    return { :value => uint64(rw, val[:value]), :pk_script => string(rw, val[:pk_script]) }
  end


  #
  # Message definitions.
  #
  def message_defs
    return @message_defs if @message_defs

    uint32 = self.method(:uint32)
    uint64 = self.method(:uint64)
    string = self.method(:string)

    net_addr   = self.method(:net_addr)
    relay_flag = self.method(:relay_flag)

    array = self.method(:array).to_proc

    hash256    = self.method(:hash256)

    inv_vect   = self.method(:inv_vect)

    block_hash = self.method(:block_hash)
    tx_hash    = self.method(:tx_hash)

    outpoint   = self.method(:outpoint)
    tx_in      = self.method(:tx_in)
    tx_out     = self.method(:tx_out)


    return @message_defs = {
      :version => [
        [:version,   uint32],
        [:services,  uint64],
        [:timestamp, uint64],
        [:your_addr, net_addr],
        [:my_addr,   net_addr],
        [:nonce,     uint64],
        [:agent,     string],
        [:height,    uint32],
        [:relay,     relay_flag]
      ],
      :verack => [],
      :mempool => [],
      :addr => [[:addr, array.curry[net_addr]]],
      :inv  => [[:inventory,  array.curry[inv_vect]]],
      :merkleblock => [
        [:hash,        block_hash],
        [:version,     uint32],
        [:prev_block,  hash256],
        [:merkle_root, hash256],
        [:timestamp,   uint32],
        [:bits,        uint32],
        [:nonce,       uint32],
        [:total_txs,   uint32],
        [:hashes,      array.curry[hash256]],
        [:flags,       string]
      ],
      :tx => [
        [:hash,      tx_hash],
        [:version,   uint32],
        [:tx_in,     array.curry[tx_in]],
        [:tx_out,    array.curry[tx_out]],
        [:lock_time, uint32]
      ],
      :filterload => [
        [:filter,     string],
        [:hash_funcs, uint32],
        [:tweak,      uint32],
        [:flag,       uint8]
      ],
      :getblocks => [
        [:version,       uint32],
        [:block_locator, array.curry[hash256]],
        [:hash_stop,     hash256]
      ],
      :getdata => [[:inventory, array.curry[inv_vect]]]
    }
  end

  #
  # Constants used in inventory vector
  #
  MSG_TX = 1
  MSG_BLOCK = 2
  MSG_FILTERED_BLOCK = 3

  #
  # Send version message to the remote host.
  #
  def send_version
    write_message({
      :command => :version,

      :version   => PROTOCOL_VERSION,

      # This client should not be asked for full blocks.
      :services  => 0,

      :timestamp => Time.now.to_i,

      :your_addr => nil, # I found that at least Satoshi client doesn't check it,
      :my_addr   => nil, # so it will be enough for this client.
      
      :nonce     => (rand(1 << 64) - 1), # A random number.

      :agent     => '/bcwallet.rb:1.00/',
      :height    => (@data[:blocks].length - 1), # Height of possessed blocks

      # It forces the remote host not to send any 'inv' messages till it receive 'filterload' message.
      :relay     => false
    })
  end

  #
  # Send filterload message.
  #
  def send_filterload
    hash_funcs = 10
    tweak = rand(1 << 32) - 1

    bf = BloomFilter.new(512, hash_funcs, tweak) 

    @keys.each do |_, key|
      bf.insert(key.to_public_key)
      bf.insert(key.to_public_key_hash)
    end

    write_message({
      :command => :filterload,

      :filter     => bf.to_s,
      :hash_funcs => hash_funcs,
      :tweak      => tweak,

      # BLOOM_UPDATE_ALL, updates Bloom filter automatically when the client has found matching transactions.
      :flag       => 1
    })
  end

  #
  # Send getblocks message until it receive all the blocks.
  # If it receives all the blocks, it will return true. Otherwise, it returns false.
  #
  def send_getblocks
    weight = 50
    perc = (weight * @data[:blocks].length / @data[:last_height]).to_i
    @status = '|' + '=' * perc + '_' * (weight - perc) +
      "| #{(@data[:blocks].length - 1)} / #{@data[:last_height]} "

    # @data[:blocks].length includes block #0 while @data[:last_height] does not.
    if @data[:blocks].length > @data[:last_height] then
      save_data
      return true
    end

    if @data[:blocks].empty? then
      send_getdata([{:type => MSG_FILTERED_BLOCK, :hash => @last_hash[:hash]}])
    end

    write_message({
      :command => :getblocks,

      :version => PROTOCOL_VERSION,
      :block_locator => [@last_hash[:hash]],
      :hash_stop => ['00' * 32].pack('H*')
    })

    return false
  end

  #
  # Send getdata message for the inventory while rewriting MSG_BLOCK to MSG_FILTERED_BLOCK
  #
  def send_getdata(inventory)
    write_message({
      :command => :getdata,

      :inventory => inventory.collect do |elm|
        # receive merkleblock instead of usual block
        {:type => (elm[:type] == MSG_BLOCK ? MSG_FILTERED_BLOCK : elm[:type]),
         :hash => elm[:hash]}
      end
    })

    return
  end

  #
  # Send inv message when you created a transaction
  #
  def send_transaction_inv
    serialize_message(@created_transaction)

    @created_transaction[:hash] = Key.hash256(@payload)
    
    write_message({
      :command => :inv,
      :inventory => [{:type => MSG_TX, :hash => hash}]
    })
  end

  #
  # Send transaction message you created
  #
  def send_transaction
    write_message(@created_transaction)

    @socket.flush

    sleep 30

    @data[:txs][@created_transaction[:hash]] = @created_transaction

    save_data
  end

  #
  # This checks whether the block has previous 5 (= threshold) blocks
  # in the received data.
  #
  def is_too_high(hash)
    threshold = 5
    cur = 0
    while @data[:blocks].has_key?(hash) && cur < threshold
      hash = @data[:blocks][hash][:prev_block]
      cur += 1
    end
    return cur == threshold
  end

  #
  # This is a heuristic function, to find out whether the block is independent young block,
  # which is not actually the last block you received through getblocks -> inv -> getdata iteration.
  #
  # In a more robust way, you have to construct graph from received blocks,
  # do a lot of validations, and actually take the longest block chain.
  #
  # The reason why the client take this way is its performance.
  # I can imagine a lot of code to realize this in C++, however,
  # doing it in Ruby is painful and also it's not ciritical to explain how Bitcoin client works.
  #
  def is_young_block(hash)
    return (@data[:blocks][hash][:timestamp] - Time.now.to_i).abs <= 60 * 60 && !is_too_high(hash)
  end

  #
  # Dispatch messages. It reads message from the remote host,
  # send proper messages back, and then again wait for a message.
  # It's like Win32 event procedure.
  #
  # Returns true if the whole process has been finished, otherwise false.
  #
  def dispatch_message
    message = read_message

    case message[:command]
    when :version
      # This is handshake process: 

      # Me -- version -> You
      # Me <- version -- You
      # Me -- verack  -> You
      # Me <- verack  -- You

      # You've got the last block height.
      @data[:last_height] = message[:height]
      save_data

      write_message({:command => :verack})

    when :verack
      # Handshake finished, so you can do anything you want.

      # Set Bloom filter
      send_filterload

      # Tell the remote host to send transactions (inv) it has in its memory pool.
      write_message({:command => :mempool})

      # Send getblocks on demand and return true
      return true if send_getblocks

    when :inv
      send_getdata message[:inventory]

      # Memorize number of requests to check whether the client have received all transactions it required.
      @requested_data += message[:inventory].length

    when :merkleblock
      @received_data += 1

      @data[:blocks][message[:hash]] = message

      # Described in is_young_block().
      # It supposes that blocks are sent in its height order. Don't try this at real code.
      unless is_young_block(message[:hash]) then
        @last_hash = { :timestamp => message[:timestamp], :hash => message[:hash] }
      end

      return true if @requested_data <= @received_data && send_getblocks

    when :tx
      @received_data += 1

      @data[:txs][message[:hash]] = message

      return true if @requested_data <= @received_data && send_getblocks

    when :getdata
      @status = 'sending transaction data ... '

      # Send the transaction you create
      send_transaction
      
      return true
    end

    return false
  end

  #
  # Set spent flags for all tx_outs.
  # If the tx_out is already spent on another transaction's tx_in, it will be set.
  # 
  def set_spent_for_tx_outs
    @data[:txs].each do |tx_hash, tx|
      tx[:tx_in].each do |tx_in|
        hash = tx_in[:previous_output][:hash]
        index = tx_in[:previous_output][:index]
        if @data[:txs].has_key?(hash) then
          @data[:txs][hash][:tx_out][index][:spent] = true
        end
      end
    end
  end

  #
  # Bitcoin has complex scripting system for its payment,
  # but we will only support very basic one.
  #
  def extract_public_key_hash_from_script(script)
    # OP_DUP OP_HASH160 (public key hash) OP_EQUALVERIFY OP_CHECKSIG
    unless script[0, 3]  == ['76a914'].pack('H*') &&
           script[23, 2] == ['88ac'].pack('H*') &&
           script.length == 25 then
      raise 'unsupported script format' 
    end

    return script[3, 20]
  end

end


#
# The class deals with command line arguments and the key file.
#
class BCWallet
  private

  def usage(error = nil)
    warn "bcwallet.rb: #{error}\n\n" if error
    warn "bcwallet.rb: Educational Bitcoin Client"
    warn "Usage: ruby bcwallet.rb <command> [<args>]"
    warn "commands:"
    warn "    generate <name>\t\tgenerate a new Bitcoin address"
    warn "    list\t\t\tshow list for all Bitcoin addresses"
    warn "    export <name>\t\tshow private key for the Bitcoin address"
    warn "    balance\t\t\tshow balances for all Bitcoin addresses"
    warn "    send <name> <to> <amount>\ttransfer coins to the Bitcoin address"
  end

  def require_args(number)
    if @argv.length < number + 1 then
      usage 'missing arguments'
      return true
    else
      return false
    end
  end

  def load_keys
    @keys = {}

    return unless File.exists?(@keys_file_name)

    open(@keys_file_name, 'r') do |file|
      file.read.lines.each do |line|
        name, der = line.split(' ')
        @keys[name] = Key.new(der)
      end
    end
  end

  def init_network
    @network = Network.new(@keys, @data_file_name)
  end

  def wait_for_sync(mode = nil)
    @network.sync

    rotate = ['/', '-', '\\', '|']
    cur = 0

    while !@network.sync_finished?
      STDERR.print "#{@network.status}#{rotate[cur]}\r"

      cur = (cur + 1) % rotate.length

      sleep 0.1
    end

    STDERR.print "#{@network.status}done.\n"
    if mode == :tx then
      STDERR.print "Transaction sent.\n\n"
    else
      STDERR.print "Block chain synchronized.\n\n"
    end
  end

  def generate(name)
    return usage "the name \"#{name}\" already exists" if @keys.has_key?(name)

    key = Key.new

    open(@keys_file_name, 'a') do |file|
      file.write "#{name} #{key.to_der_hex_s}\n"
    end

    puts "new Bitcoin address \"#{name}\" generated: #{key.to_address_s}"
  end

  def list
    if @keys.empty? then
      puts 'No addresses available'
      return
    end

    puts 'List of available Bitcoin addresses: '
    @keys.each do |name, key|
      puts "    #{name}: #{key.to_address_s}"
    end
  end

  def export(name)
    return usage "an address named #{name} doesn't exist" unless @keys.has_key?(name)

    STDERR.print "Are you sure you want to export private key for \"#{name}\"? (yes/no): "

    if STDIN.gets.chomp.downcase == 'yes' then
      puts @keys[name].to_private_key_s
    end
  end

  def balance
    STDERR.print "loading data ...\r"

    init_network
    wait_for_sync

    puts 'Balances for available Bitcoin addresses: '

    balance = @network.get_balance
    balance.each do |addr, satoshi|
      puts "    #{ addr }: #{ sprintf('%.8f', Rational(satoshi, 10**8)) } BTC"
    end
  end

  def send(name, to, amount)
    return usage "an address named #{name} doesn't exist" unless @keys.has_key?(name)

    init_network
    wait_for_sync

    STDERR.print "Are you sure you want to send\n"
    STDERR.print "    #{sprintf('%.8f', amount * Rational(1, 10**8))} BTC\n"
    STDERR.print "from\n    \"#{name}\"\nto\n    \"#{to}\"\n? (yes/no): "

    if STDIN.gets.chomp.downcase == 'yes' then
      @network.send(@keys[name], to, amount)

      wait_for_sync
    end
  end

  def block(hash)
    init_network
    p @network.data[:blocks][[hash].pack('H*').reverse]
  end

  public

  def initialize(argv, keys_file_name, data_file_name)
    @argv = argv
    @keys_file_name = keys_file_name
    @data_file_name = data_file_name
    @network = nil
  end

  def run
    return usage if @argv.length < 1

    load_keys

    case @argv.first
    when 'generate'
      return if require_args(1)

      # name = @argv[1]
      generate(@argv[1])

    when 'list'
      list

    when 'export'
      return if require_args(1)

      # name = @argv[1]
      export(@argv[1])

    when 'balance'
      balace

    when 'send'
      return if require_args(3)

      # name = @argv[1], to = @argv[2], amount = @argv[3] (converted into satoshi)
      send(@argv[1], @argv[2], @argv[3].to_r * Rational(10 ** 8))

    when 'block'
      return if require_args(1)

      # hash = @argv[1]
      block(@argv[1])

    else
      return usage 'invalid command'
    end
  end
end

if caller.length == 0 then
  unless IS_TESTNET
    warn 'WARNING: RUNNING UNDER MAIN NETWORK MODE'
  end

  key_file_name = IS_TESTNET ? 'keys_testnet' : 'keys'
  data_file_name = IS_TESTNET ? 'data_testnet' : 'data'

  bcwallet = BCWallet.new(ARGV, key_file_name, data_file_name)

  bcwallet.run
end

