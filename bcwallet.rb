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
  #
  # Bitcoin mainly uses SHA-256(SHA-256(plain)) as a cryptographic hash function
  # when a hash is needed.
  #
  def self.hash256(plain)
    OpenSSL::Digest::SHA256.digest(OpenSSL::Digest::SHA256.digest(plain))
  end

  #
  # RIPEMD-160(SHA-256(plain)) is used when a shorter hash is preferable.
  #
  def self.hash160(plain)
    OpenSSL::Digest::RIPEMD160.digest(OpenSSL::Digest::SHA256.digest(plain))
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

    res.reverse
  end

  def self.decode_base58(encoded)
    num = 0
    encoded.each_char do |c|
      num *= 58
      num += BASE58.index(c)
    end

    res = num.to_s(16)

    if res.length % 2 == 1
      res = '0' + res
    end

    # restore leading zeroes
    encoded.each_char do |c|
      break if c != BASE58[0]
      res = '00' + res
    end

    [res].pack('H*')
  end

  #
  # Base58 with the type of data and the checksum is called Base58Check in Bitcoin protocol.
  # It is used as a Bitcoin address, human-readable private key, etc.
  #
  def self.encode_base58check(type, plain)
    leading_bytes = {
      main:    { public_key: 0,   private_key: 128 },
      testnet: { public_key: 111, private_key: 239 }
    }

    leading_byte = [leading_bytes[IS_TESTNET ? :testnet : :main][type]].pack('C')

    data = leading_byte + plain
    checksum = Key.hash256(data)[0, 4]

    Key.encode_base58(data + checksum)
  end

  def self.decode_base58check(encoded)
    decoded = Key.decode_base58(encoded)

    raise "invalid base58 checksum" if Key.hash256(decoded[0, decoded.length - 4])[0, 4] != decoded[-4, 4]

    types = {
      main:    { 0   => :public_key, 128 => :private_key },
      testnet: { 111 => :public_key, 239 => :private_key }
    }

    type = types[IS_TESTNET ? :testnet : :main][decoded[0].unpack('C').first]

    { type: type, data: decoded[1, decoded.length - 5] }
  end

  #
  # Initialize with ASCII-encoded DER format string (nil to generate a new key)
  #
  def initialize(der = nil)
    if der
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
    @key.dsa_sign_asn1(data)
  end

  #
  # Convert public key to Bitcoin address.
  #
  def to_address_s
    Key.encode_base58check(:public_key, Key.hash160(@key.public_key.to_bn.to_s(2)))
  end

  # 
  # Convert the private key to Bitcoin private key import format.
  #
  def to_private_key_s
    Key.encode_base58check(:private_key, @key.private_key.to_s(2))
  end

  #
  # Convert the key pair into ASCII-encoded DER format string.
  #
  def to_der_hex_s
    @key.to_der.unpack('H*').first
  end

  def to_public_key
    @key.public_key.to_bn.to_s(2)
  end

  def to_public_key_hash
    Key.hash160(@key.public_key.to_bn.to_s(2))
  end
end

#
# A class which generates Bloom filter.
# Bloom filter is a data structure used in Bitcoin to filter transactions for SPV clients.
# It enables you to quickly test whether an element is included in a set,
# but may have false positives (i.e. probabilistic data structure).
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
    ((x << r) | (x >> (32 - r))) & 0xffffffff
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

    h1
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
    res
  end
end

#
# A class for message serializers and deserializers.
# It contains type definitions of structures.
#
class Message
  #
  # Constants used in inventory vector
  #
  MSG_TX = 1
  MSG_BLOCK = 2
  MSG_FILTERED_BLOCK = 3


  def initialize
    #
    # Message definitions.
    #
    @message_definitions = {
      version: [
        [:version,   :uint32],
        [:services,  :uint64],
        [:timestamp, :uint64],
        [:your_addr, :net_addr],
        [:my_addr,   :net_addr],
        [:nonce,     :uint64],
        [:agent,     :string],
        [:height,    :uint32],
        [:relay,     :relay_flag]
      ],
      ping:    [[:nonce, :uint64]],
      pong:    [[:nonce, :uint64]],
      alert:   [],
      verack:  [],
      mempool: [],
      addr:    [[:addr, array_for(:net_addr)]],
      inv:     [[:inventory,  array_for(:inv_vect)]],
      merkleblock: [
        [:hash,        :block_hash],
        [:version,     :uint32],
        [:prev_block,  :hash256],
        [:merkle_root, :hash256],
        [:timestamp,   :uint32],
        [:bits,        :uint32],
        [:nonce,       :uint32],
        [:total_txs,   :uint32],
        [:hashes,      array_for(:hash256)],
        [:flags,       :string]
      ],
      tx: [
        [:hash,      :tx_hash],
        [:version,   :uint32],
        [:tx_in,     array_for(:tx_in)],
        [:tx_out,    array_for(:tx_out)],
        [:lock_time, :uint32]
      ],
      filterload: [
        [:filter,     :string],
        [:hash_funcs, :uint32],
        [:tweak,      :uint32],
        [:flag,       :uint8]
      ],
      getblocks: [
        [:version,       :uint32],
        [:block_locator, array_for(:hash256)],
        [:hash_stop,     :hash256]
      ],
      getdata: [[:inventory, array_for(:inv_vect)]],
      inv_vect: [
        [:type, :uint32],
        [:hash, :hash256]],
      outpoint: [
        [:hash, :hash256],
        [:index, :uint32]],
      tx_in: [
        [:previous_output, :outpoint],
        [:signature_script, :string],
        [:sequence, :uint32]],
      tx_out: [
        [:value, :uint64],
        [:pk_script, :string]]
    }
  end

  #
  # Serialize a message using message definitions.
  #
  def serialize(message)
    @payload = ''

    serialize_struct(message[:command], message)

    @payload
  end

  #
  # Deserialize a message using message definitions.
  #
  def deserialize(command, payload)
    raise unless @message_definitions.has_key?(command)

    @payload = payload

    res = deserialize_struct(command)
    res[:command] = command

    res
  end

  # 
  # Read a message and parse it using message definitions.
  #
  def read(socket)
    packet = read_packet(socket)

    expected_magic    = [IS_TESTNET ? '0b110907' : 'f9beb4d9'].pack('H*')
    expected_checksum = Key.hash256(packet[:payload])[0, 4]

    if packet[:magic] != expected_magic
      raise 'invalid magic received'
    end

    if packet[:checksum] != expected_checksum
      raise 'incorrect checksum'
    end

    unless @message_definitions.has_key?(packet[:command])
      raise 'invalid message type'
    end

    deserialize(packet[:command], packet[:payload])
  end

  #
  # Actually send a message to the remote host.
  #
  def write(socket, message)
    # Create payload
    payload = serialize(message)

    # 4bytes: magic
    raw_message = [IS_TESTNET ? '0b110907' : 'f9beb4d9'].pack('H*')

    # 12bytes: command (padded with zeroes)
    raw_message += [message[:command].to_s].pack('a12')

    # 4bytes: length of payload
    raw_message += [payload.length].pack('V')

    # 4bytes: checksum
    raw_message += Key.hash256(payload)[0, 4]

    # payload
    raw_message += payload

    socket.write raw_message
    socket.flush
  end

  private

  def read_packet(socket)
    magic    = socket.read(4)
    command  = socket.read(12).unpack('A12').first.to_sym
    length   = socket.read(4).unpack('V').first
    checksum = socket.read(4)
    payload  = socket.read(length)

    { magic: magic, command: command, checksum: checksum, payload: payload }
  end

  def serialize_struct(type, struct)
    if type.kind_of?(Proc)
      type.call(:write, struct)
      return
    end

    if @message_definitions.has_key?(type)
      @message_definitions[type].each do |definition|
        next if struct.has_key?(:command) && definition.first == :hash
        serialize_struct(definition.last, struct[definition.first])
      end
    else
      method(type).call(:write, struct)
    end
  end

  def deserialize_struct(type)
    if type.kind_of?(Proc)
      return type.call(:read)
    end

    if @message_definitions.has_key?(type)
      res = {}
      @message_definitions[type].each do |definition|
        res[definition.first] = deserialize_struct(definition.last)
      end
      res
    else
      method(type).call(:read)
    end
  end

  #
  # Higher order function to generate array serializer / deserializer
  #
  def array_for(elm)
    lambda do |rw, val = nil|
      case rw
      when :read
        count = integer(:read)
        res = []
        count.times do
          res.push deserialize_struct(elm)
        end
        res
      when :write
        integer(:write, val.length)
        val.each do |v|
          serialize_struct(elm, v)
        end
        val
      end
    end
  end

  #
  # Serializer & deserializer methods
  #

  def read_bytes(len)
    res = @payload[0, len]
    @payload = @payload[len..-1]
    res
  end

  def write_bytes(val)
    @payload += val
  end

  def fixed_integer(templ, len, rw, val = nil)
    case rw
    when :read 
      read_bytes(len).unpack(templ).first
    when :write
      write_bytes([val].pack(templ))
    end
  end

  def uint8(rw, val = nil)
    fixed_integer('C', 1, rw, val)
  end

  def uint16(rw, val = nil)
    fixed_integer('v', 2, rw, val)
  end

  def uint32(rw, val = nil)
    fixed_integer('V', 4, rw, val)
  end

  def uint64(rw, val = nil)
    fixed_integer('Q', 8, rw, val)
  end

  def read_integer
    top = uint8(:read)
    case top
    when 0xfd then uint16(:read)
    when 0xfe then uint32(:read)
    when 0xff then uint64(:read)
    else top
    end
  end

  def write_integer(val)
    if val < 0xfd
      uint8(:write, val)
    elsif val <= 0xffff
      uint8(:write, 0xfd)
      uint16(:write, val)
    elsif val <= 0xffffffff
      uint8(:write, 0xfe)
      uint32(:write, val)
    else
      uint8(:write, 0xff)
      uint64(:write, val)
    end
  end

  def integer(rw, val = nil)
    case rw
    when :read
      read_integer
    when :write
      write_integer(val)
    end
  end

  def string(rw, val = nil)
    case rw
    when :read
      len = integer(:read)
      read_bytes(len)
    when :write
      integer(:write, val.length)
      write_bytes(val)
      val
    end
  end

  def net_addr(rw, val = nil)
    # accurate serializing is not necessary
    case rw
    when :read
      read_bytes(26)
      nil
    when :write
      write_bytes([0, '00000000000000000000FFFF', '00000000', 8333].pack('QH*H*n'))
      val
    end
  end

  def relay_flag(rw, val = nil)
    case rw
    when :read
      if @payload.length > 0
        uint8(:read)
      else
        true
      end
    when :write
      unless val
        uint8(:write, 0)
      end
      val
    end
  end

  def hash256(rw, val = nil)
    case rw
    when :read
      read_bytes(32)
    when :write
      write_bytes(val)
      val
    end
  end

  def block_hash(rw, val = nil)
    case rw
    when :read
      Key.hash256(@payload[0, 80])
    end
  end

  def tx_hash(rw, val = nil)
    case rw
    when :read
      Key.hash256(@payload)
    end
  end
end

#
# The blockchain class. It manages and stores Bitcoin blockchain data.
#
class Blockchain
  def initialize(keys, data_file_name)
    @data_file_name = data_file_name

    keys_hash = Key.hash256(keys.collect { |key, _| key }.sort.join)

    init_data(keys_hash)
    load_data

    # new keys are added since the last synchronization
    init_data(keys_hash) if @data[:keys_hash] != keys_hash
  end

  def init_data(keys_hash)
    @data = { blocks: {}, txs: {}, last_height: 0, keys_hash: keys_hash }
  end

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

  def calc_last_hash
    # These hashes are genesis blocks' ones.
    last_hash = { timestamp: 0,
                   hash: [IS_TESTNET ?
                     '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943' :
                     '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'].pack('H*').reverse }

    @data[:blocks].each do |hash, block|
      if block[:timestamp] > last_hash[:timestamp]
        last_hash = { timestamp: block[:timestamp], hash: hash }
      end
    end

    last_hash
  end

  def blocks
    @data[:blocks]
  end

  def txs
    @data[:txs]
  end

  def last_height
    @data[:last_height]
  end

  def last_height=(v)
    @data[:last_height] = v
  end

  #
  # Get balance for the keys
  #
  def get_balance(keys)
    balance = {}
    keys.each do |addr, _|
      balance[addr] = 0
    end

    set_spent_for_tx_outs!

    @data[:txs].each do |tx_hash, tx|
      keys.each do |addr, key|
        public_key_hash = key.to_public_key_hash

        tx[:tx_out].each do |tx_out|
          # The tx_out was already spent
          next if tx_out[:spent]

          if extract_public_key_hash_from_script(tx_out[:pk_script]) == public_key_hash
            balance[addr] += tx_out[:value]
          end
        end
      end
    end

    balance
  end

  #
  # This is a heuristic function to find out whether the block is an independent young block.
  # An independent block here means a block which have not received one of its ancestors yet.
  # We may receive this kind of blocks regardless of getblocks -> inv -> getdata iteration.
  #
  # To implement it more robustly, you have to construct graph from received blocks,
  # do a lot of validations, and actually take the longest block chain.
  #
  # The reason why the client took this way is simplicity and performance.
  # Doing them in Ruby is painful, and also it's not ciritical to explain how Bitcoin client works.
  #
  def is_young_block(hash)
    (@data[:blocks][hash][:timestamp] - Time.now.to_i).abs <= 60 * 60 && !is_too_high(hash)
  end

  def accumulate_txs(from_key, amount)
    public_key_hash = from_key.to_public_key_hash

    # Refresh spent flags of tx_outs
    set_spent_for_tx_outs!

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

        if extract_public_key_hash_from_script(tx_out[:pk_script]) == public_key_hash
          total_satoshis += tx_out[:value]
          matched = index
          pk_script = tx_out[:pk_script]
          break
        end
      end

      if matched
        tx_in.push({ previous_output:  { :hash => tx[:hash], :index => matched },
                     signature_script: '',
                     sequence:         ((1 << 32) - 1),

                     # not included in serialized data, but used to make signature
                     pk_script: pk_script })
      end
    end

    { total_satoshis: total_satoshis, tx_in: tx_in }
  end

  #
  # Set spent flags for all tx_outs.
  # If the tx_out is already spent on another transaction's tx_in, it will be set.
  # 
  def set_spent_for_tx_outs!
    @data[:txs].each do |tx_hash, tx|
      tx[:tx_in].each do |tx_in|
        hash = tx_in[:previous_output][:hash]
        index = tx_in[:previous_output][:index]
        if @data[:txs].has_key?(hash)
          @data[:txs][hash][:tx_out][index][:spent] = true
        end
      end
    end
  end

  private

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
    cur == threshold
  end

  #
  # Bitcoin has complex scripting system for its payment,
  # but we will only support very basic one.
  #
  def extract_public_key_hash_from_script(script)
    # OP_DUP OP_HASH160 (public key hash) OP_EQUALVERIFY OP_CHECKSIG
    unless script[0, 3]  == ['76a914'].pack('H*') &&
           script[23, 2] == ['88ac'].pack('H*') &&
           script.length == 25
      raise 'unsupported script format' 
    end

    script[3, 20]
  end
end

#
# The network class. It may be split into two or three classes
# to manage multiple connections and features in production.
#
class Network
  attr_reader :status, :data

  # 
  # keys = { name => ECDSA key objects }
  #
  def initialize(keys, data_file_name)
    @message = Message.new

    @keys = keys

    @blockchain = Blockchain.new(@keys, data_file_name)
    @last_hash = @blockchain.calc_last_hash

    @is_sync_finished = true

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

      unless @socket
        @status = 'connection establishing ... '

        @socket = TCPSocket.open(HOST, IS_TESTNET ? 18333 : 8333)

        send_version
      end

      if @created_transaction
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
    @is_sync_finished
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
    if to_addr_decoded[:type] != :public_key
      raise 'invalid address'
    end

    accumulated = @blockchain.accumulate_txs(from_key, amount)

    payback = accumulated[:total_satoshis] - amount - transaction_fee
    unless payback >= 0
      raise "you don't have enough balance to pay"
    end

    @created_transaction = sign_transaction(from_key, {
      command: :tx,

      version: 1,

      tx_in: accumulated[:tx_in],
      tx_out: [{ value: amount,  pk_script: generate_pk_script(to_addr_decoded[:data]) },
               { value: payback, pk_script: generate_pk_script(from_key.to_public_key_hash) }],

      lock_time: 0
    })

    @status = ''
  end

  #
  # Get balance for the keys
  #
  def get_balance
    @blockchain.get_balance(@keys)
  end


  def block(hash)
    @blockchain.blocks[hash]
  end

  private

  PROTOCOL_VERSION = 70002

  #
  # Send version message to the remote host.
  #
  def send_version
    @message.write(@socket, {
      command: :version,

      version:   PROTOCOL_VERSION,

      # This client should not be asked for full blocks.
      services:  0,

      timestamp: Time.now.to_i,

      your_addr: nil, # I found that at least Satoshi client doesn't check it,
      my_addr:   nil, # so it will be enough for this client.
      
      nonce:     (rand(1 << 64) - 1), # A random number.

      agent:     '/bcwallet.rb:1.00/',
      height:    (@blockchain.blocks.length - 1), # Height of possessed blocks

      # It forces the remote host not to send any 'inv' messages till it receive 'filterload' message.
      relay:     false
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

    @message.write(@socket, {
      command: :filterload,

      filter:     bf.to_s,
      hash_funcs: hash_funcs,
      tweak:      tweak,

      # BLOOM_UPDATE_ALL, updates Bloom filter automatically when the client has found matching transactions.
      flag:       1
    })
  end

  def refresh_status
    weight = 50
    perc = (weight * @blockchain.blocks.length / @blockchain.last_height).to_i
    @status = '|' + '=' * perc + '_' * [weight - perc, 0].max +
      "| #{(@blockchain.blocks.length - 1)} / #{@blockchain.last_height} "
  end

  #
  # Send getblocks message until it receive all the blocks.
  # If it receives all the blocks, it will return true. Otherwise, it returns false.
  #
  def send_getblocks
    refresh_status

    # @blockchain.blocks.length includes block #0 while @blockchain.last_height does not.
    if @blockchain.blocks.length > @blockchain.last_height
      @blockchain.save_data
      return true
    end

    if @blockchain.blocks.empty?
      send_getdata([{type: Message::MSG_FILTERED_BLOCK, hash: @last_hash[:hash]}])
    end

    @message.write(@socket, {
      command: :getblocks,

      version: PROTOCOL_VERSION,
      block_locator: [@last_hash[:hash]],
      hash_stop: ['00' * 32].pack('H*')
    })

    false
  end

  #
  # Send getdata message for the inventory while rewriting MSG_BLOCK to MSG_FILTERED_BLOCK
  #
  def send_getdata(inventory)
    @message.write(@socket, {
      command: :getdata,

      inventory: inventory.collect do |elm|
        # receive merkleblock instead of usual block
        {type: (elm[:type] == Message::MSG_BLOCK ? Message::MSG_FILTERED_BLOCK : elm[:type]),
         hash: elm[:hash]}
      end
    })
  end

  #
  # Send inv message when you created a transaction
  #
  def send_transaction_inv
    payload = @message.serialize(@created_transaction)

    @created_transaction[:hash] = Key.hash256(payload)
    
    @message.write(@socket, {
      command: :inv,
      inventory: [{type: Message::MSG_TX, hash: @created_transaction[:hash]}]
    })
  end

  #
  # Send transaction message you created
  #
  def send_transaction
    @message.write(@socket, @created_transaction)

    @socket.flush

    sleep 30

    @blockchain.txs[@created_transaction[:hash]] = @created_transaction

    @blockchain.save_data
  end

  #
  # Dispatch messages. It reads message from the remote host,
  # send proper messages back, and then again wait for a message.
  #
  # Returns true if the whole process has been finished, otherwise false.
  #
  def dispatch_message
    message = @message.read(@socket)

    case message[:command]
    when :version     then dispatch_version(message)
    when :ping        then dispatch_ping(message)
    when :inv         then dispatch_inv(message)
    when :merkleblock then dispatch_merkleblock(message)
    when :tx          then dispatch_tx(message)
    when :getdata     then dispatch_getdata(message)
    end
  end

  def dispatch_version(message)
    # This is handshake process: 

    # Local -- version -> Remote
    # Local <- version -- Remote
    # Local -- verack  -> Remote
    # Local <- verack  -- Remote
    # Local <- ping    -- Remote
    # Local -- pong    -> Remote

    # You've got the latest block height.
    @blockchain.last_height = message[:height]
    @blockchain.save_data

    @message.write(@socket, {command: :verack})

    false
  end

  def dispatch_ping(message)
    # Reply with pong
    @message.write(@socket, {command: :pong, nonce: message[:nonce]})

    # Handshake finished, so you can do anything you want.

    # Set Bloom filter
    send_filterload

    # Tell the remote host to send transactions (inv) it has in its memory pool.
    @message.write(@socket, {command: :mempool})

    # Send getblocks on demand and return true
    send_getblocks

  end

  def dispatch_inv(message)
    send_getdata message[:inventory]

    # Memorize number of requests to check whether the client have received all transactions it required.
    @requested_data += message[:inventory].length

    false
  end

  def dispatch_merkleblock(message)
    @received_data += 1

    @blockchain.blocks[message[:hash]] = message

    # Described in Blockchain#is_young_block.
    # It supposes that blocks are sent in its height order. Don't try this in production code.
    unless @blockchain.is_young_block(message[:hash])
      @last_hash = { timestamp: message[:timestamp], hash: message[:hash] }
    end

    @requested_data <= @received_data && send_getblocks
  end

  def dispatch_tx(message)
    @received_data += 1

    @blockchain.txs[message[:hash]] = message

    @requested_data <= @received_data && send_getblocks
  end

  def dispatch_getdata(message)
    @status = 'sending transaction data ... '

    # Send the transaction you create
    send_transaction

    true
  end

  def sign_transaction(from_key, transaction)
    # We have generated all data without signatures, so we're now going to generate signatures.
    # However, it is very complicated one.
    signatures = []

    transaction[:tx_in].length.times do |i|
      signatures.push(sign_transaction_of_idx(i))
    end

    signatures.each_with_index do |signature, i|
      transaction[:tx_in][i][:signature_script] = generate_signature_script(signature, from_key)
    end

    return transaction
  end

  def sign_transaction_of_idx(from_key, transaction, i)
    duplicated            = transaction.dup
    duplicated[:tx_in]    = duplicated[:tx_in].dup
    duplicated[:tx_in][i] = duplicated[:tx_in][i].dup

    # To generate signature, you need hash256 of the whole transaction in special form.
    # The transaction in that form is different in a way that the signature_script
    # field in the tx_in to sign is replaced with pk_script in previous tx_out,
    # and other tx_ins' signature_scripts are empty.
    # (make sure that var_int for the length is also set to zero)
    #
    # For further information, see: 
    #   https://en.bitcoin.it/w/images/en/7/70/Bitcoin_OpCheckSig_InDetail.png
    #

    duplicated[:tx_in][i][:signature_script] = transaction[:tx_in][i][:pk_script]

    payload = @message.serialize(duplicated)

    # hash256 includes type code field (see the figure in the URL above)
    verified_str = Key.hash256(payload + [1].pack('V'))

    from_key.sign(verified_str)
  end

  def generate_pk_script(public_key_hash)
    # pk_script field is constructed in Bitcoin's scripting system
    #    https://en.bitcoin.it/wiki/Script
    #
    prefix = ['76a914'].pack('H*') # OP_DUP OP_HASH160 [length of the address]
    postfix = ['88ac'].pack('H*')  # OP_EQUALVERIFY OP_CHECKSIG

    prefix + public_key_hash + postfix
  end

  def generate_signature_script(signature, from_key)
    # see the figure in the
    #   https://en.bitcoin.it/w/images/en/7/70/Bitcoin_OpCheckSig_InDetail.png

    public_key = from_key.to_public_key

    script = [signature.length + 1].pack('C') + signature + [1].pack('C')
    script += [public_key.length].pack('C') + public_key

    script
  end
end


#
# The class deals with command line arguments and the key file.
#
class BCWallet
  def initialize(argv, keys_file_name, data_file_name)
    @argv = argv
    @keys_file_name = keys_file_name
    @data_file_name = data_file_name
    @network = nil
  end

  def run
    return usage if @argv.length < 1

    # check argument numbers
    case @argv.first
    when 'generate' then return if require_args(1)
    when 'list'     then return if require_args(0)
    when 'export'   then return if require_args(1)
    when 'balance'  then return if require_args(0)
    when 'send'     then return if require_args(3)
    when 'block'    then return if require_args(1)
    else
      usage 'invalid command'
      return
    end

    load_keys

    case @argv.first
    when 'generate' then generate(@argv[1]) # name
    when 'list'     then list
    when 'export'   then export(@argv[1]) # name
    when 'balance'  then balance
    when 'send'     then send(@argv[1], @argv[2], btc_to_satoshi(@argv[3].to_r)) # name, to, amount
    when 'block'    then block(@argv[1]) # hash
    end
  end

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
    if @argv.length < number + 1
      usage 'missing arguments'
      true
    else
      false
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
      $stderr.print "#{@network.status}#{rotate[cur]}\r"

      cur = (cur + 1) % rotate.length

      sleep 0.1
    end

    $stderr.print "#{@network.status}done.\n"
    if mode == :tx
      $stderr.print "Transaction sent.\n\n"
    else
      $stderr.print "Block chain synchronized.\n\n"
    end
  end

  def btc_to_satoshi(btc)
    btc * Rational(10 ** 8)
  end

  def satoshi_to_btc(satoshi)
    Rational(satoshi, 10**8)
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
    if @keys.empty?
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

    $stderr.print "Are you sure you want to export private key for \"#{name}\"? (yes/NO): "

    if $stdin.gets.chomp.downcase == 'yes'
      puts @keys[name].to_private_key_s
    end
  end

  def balance
    $stderr.print "loading data ...\r"

    init_network
    wait_for_sync

    puts 'Balances for available Bitcoin addresses: '

    balance = @network.get_balance
    balance.each do |addr, satoshi|
      puts "    #{ addr }: #{ sprintf('%.8f', satoshi_to_btc(satoshi)) } BTC"
    end
  end

  def confirm_send(name, to, amount)
    $stderr.print "Are you sure you want to send\n"
    $stderr.print "    #{sprintf('%.8f', satoshi_to_btc(amount))} BTC\n"
    $stderr.print "from\n    \"#{name}\"\nto\n    \"#{to}\"\n? (yes/no): "

    $stdin.gets.chomp.downcase == 'yes'
  end

  def send(name, to, amount)
    return usage "an address named #{name} doesn't exist" unless @keys.has_key?(name)

    init_network
    wait_for_sync

    if confirm_send(name, to, amount)
      begin
        @network.send(@keys[name], to, amount)
      rescue => e
        warn "bcwallet.rb: #{e}"
        return
      end
      wait_for_sync
    end
  end

  def block(hash)
    init_network
    puts @network.block([hash].pack('H*').reverse)
  end
end

if caller.length == 0
  unless IS_TESTNET
    warn 'WARNING: RUNNING UNDER MAIN NETWORK MODE'
  end

  key_file_name = IS_TESTNET ? 'keys_testnet' : 'keys'
  data_file_name = IS_TESTNET ? 'data_testnet' : 'data'

  bcwallet = BCWallet.new(ARGV, key_file_name, data_file_name)

  bcwallet.run
end

