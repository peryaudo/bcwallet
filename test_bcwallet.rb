if ENV['CI'] then
  require 'coveralls'
  Coveralls.wear!
end

require 'minitest/unit'
require './bcwallet'

MiniTest::Unit.autorun

class TestKey < MiniTest::Unit::TestCase
  def test_base58_encode
    assert_equal '2cFupjhnEsSn59qHXstmK2ffpLv2',
      Key.encode_base58(['73696d706c792061206c6f6e6720737472696e67'].pack('H*'))
  end

  def test_base58_decode
    assert_equal ['73696d706c792061206c6f6e6720737472696e67'].pack('H*'),
      Key.decode_base58('2cFupjhnEsSn59qHXstmK2ffpLv2')
  end

  def test_base58_encode_decode
    assert_equal 'foobarbazhoge', Key.decode_base58(Key.encode_base58('foobarbazhoge'))
  end

  def test_key_generation
    key = Key.new

    address_str = key.to_address_s
    private_key_str = key.to_private_key_s

    assert_match /[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/, address_str
    assert_match /[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/, private_key_str
  end
end

class TestBloomFilter < MiniTest::Unit::TestCase
  def test_murmur_hash
    bf = BloomFilter.new(1, 1, 1)
    assert_equal 0x2a2884ba, bf.hash(0xabcdef, "hogehoge")
    assert_equal 0xcdcbf1ad, bf.hash(0xabcdef, "foobarbaz")
    assert_equal 0xc28e9cab, bf.hash(0xabcdef, "abcdefghijklmnopqrstuvwxyz")
    assert_equal 0xfe1d612e, bf.hash(0xabcdef, "qwertyuiop")
  end
end

class TestMessage < MiniTest::Unit::TestCase
  def test_version_message_serialize
    m = Message.new
    b = m.serialize({
      command: :version,
      version: 31900,
      services: 1,
      timestamp: 1292899814,
      your_addr: nil,
      my_addr: nil,
      nonce: 1393780771635895773,
      agent: '',
      height: 98645,
      relay: true
    })

    assert_equal(b.unpack('C*'),
      [0x9C, 0x7C, 0x00, 0x00,
       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xE6, 0x15, 0x10, 0x4D, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x20, 0x8D,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x20, 0x8D,
       0xDD, 0x9D, 0x20, 0x2C, 0x3A, 0xB4, 0x57, 0x13,
       0x00,
       0x55, 0x81, 0x01, 0x00])

  end
end
