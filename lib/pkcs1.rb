# Copyright 2004, 2005  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'openssl'
require 'digest/md5'
require 'digest/sha1'
require 'digest/sha2'


module PKCS1


# 1 Introduction


# 2 Notation

module Util
module_function

  def nbits(num)
    idx = num.size * 8 - 1
    while idx >= 0
      if num[idx].nonzero?
        return idx + 1
      end
      idx -= 1
    end
    0
  end

  def divceil(a, b)
    (a + b - 1) / b
  end

  def xor(a, b)
    if a.size != b.size
      raise ArgumentError
    end
    a = a.unpack('C*')
    b = b.unpack('C*')
    a.size.times do |idx|
      a[idx] ^= b[idx]
    end
    a.pack("C*")
  end
end


# 3 Key types
module Key
  class RSAPublicKey
    attr_reader :n
    attr_reader :e

    def initialize(n, e)
      @n, @e = n, e
      @n_bn = OpenSSL::BN.new(@n.to_s)
      @e_bn = OpenSSL::BN.new(@e.to_s)
    end

    def encrypt(m)
      calc(m)
    end

    # M = S ^ e (mod n)
    def verify(s)
      if s < 0 or s >= @n
        raise ArgumentError, "signature representative out of range"
      end
      calc(s)
    end

  private

    # c = m ^ e (mod n)
    def calc(input)
      input_bn = OpenSSL::BN.new(input.to_s)
      (input_bn.mod_exp(@e_bn, @n_bn)).to_i
    end
  end


  class RSAPrivateKey
    include Util

    attr_reader :public_key
    attr_reader :version
    attr_reader :n
    attr_reader :d

    def initialize(n, e, d)
      @version = 0
      @n, @d = n, d
      @n_bn = OpenSSL::BN.new(@n.to_s)
      @d_bn = OpenSSL::BN.new(@d.to_s)
      @public_key = RSAPublicKey.new(n, e)
    end

    def modbytes
      divceil(modbits, 8)
    end

    def modbits
      nbits(@n)
    end

    def encrypt(m)
      @public_key.encrypt(m)
    end

    def decrypt(c)
      calc(c)
    end

    def sign(m)
      if m < 0 or m >= @n
        raise ArgumentError, "message representative out of range"
      end
      calc(m)
    end

    def verify(s)
      @public_key.verify(s)
    end

  private

    # s = m ^ d (mod n)
    def calc(input)
      input_bn = OpenSSL::BN.new(input.to_s)
      (input_bn.mod_exp(@d_bn, @n_bn)).to_i
    end
  end


  class RSACRTPrivateKey
    include Util

    attr_reader :public_key
    attr_reader :version
    attr_reader :n
    attr_reader :p
    attr_reader :q
    attr_reader :dp
    attr_reader :dq
    attr_reader :qinv

    def initialize(n, e, p, q, dp, dq, qinv)
      @version = 0
      @n = n
      @n_bn = OpenSSL::BN.new(@n.to_s)
      @p, @q, @dp, @dq, @qinv = p, q, dp, dq, qinv
      @p_bn = OpenSSL::BN.new(@p.to_s)
      @q_bn = OpenSSL::BN.new(@q.to_s)
      @dp_bn = OpenSSL::BN.new(@dp.to_s)
      @dq_bn = OpenSSL::BN.new(@dq.to_s)
      @qinv_bn = OpenSSL::BN.new(@qinv.to_s)
      @public_key = RSAPublicKey.new(n, e)
    end

    def modbytes
      divceil(modbits, 8)
    end

    def modbits
      nbits(@n)
    end

    def encrypt(m)
      @public_key.encrypt(m)
    end

    def decrypt(c)
      calc(c)
    end

    def sign(m)
      if m < 0 or m >= @n
        raise ArgumentError, "message representative out of range"
      end
      calc(m)
    end

    def verify(s)
      @public_key.verify(s)
    end

  private

    # s1 = m ^ dp (mod p)
    # s2 = m ^ dq (mod q)
    # h = (s1 - s2) * qinv (mod p)
    # s = s2 + q * h
    def calc(input)
      input_bn = OpenSSL::BN.new(input.to_s)
      s1 = input_bn.mod_exp(@dp_bn, @p_bn)
      s2 = input_bn.mod_exp(@dq_bn, @q_bn)
      h = @qinv_bn.mod_mul(s1 - s2, @p_bn)
      (s2 + q * h).to_i
    end
  end


  RSA = RSAPrivateKey
  RSACRT = RSACRTPrivateKey
end


# 4 Data conversion primitives
module DataConversion
module_function

  # Integer to Octet String primitive
  def i2osp(x, len)
    if x >= 256 ** len
      raise ArgumentError, "integer too large"
    end
    os = to_bytes(x).sub(/^\x00+/, '')
    "\x00" * (len - os.size) + os
  end

  # Octet String to Integer primitive
  def os2ip(x)
    from_bytes(x)
  end

  def to_bytes(num)
    bits = num.size * 8
    pos = value = 0
    str = ""
    for idx in 0..(bits - 1)
      if num[idx].nonzero?
        value |= (num[idx] << pos)
      end
      pos += 1
      if pos == 32
        str = [value].pack("N") + str
        pos = value = 0
      end
    end
    str
  end

  def from_bytes(bytes)
    num = 0
    bytes.each_byte do |c|
      num <<= 8
      num |= c
    end
    num
  end
end


# 5 Cryptographic primitives
module CryptographicPrimitive
module_function

  def rsaep(key, msg)
    key.encrypt(msg)
  end

  def rsadp(key, cipher)
    key.decrypt(cipher)
  end

  def rsasp1(key, msg)
    key.sign(msg)
  end

  def rsavp1(key, sig)
    key.verify(sig)
  end
end


# 6 Overview of schemes


# 7 Encryption schemes
module EncryptionScheme
module_function
  
  def rsaes_oaep_encrypt(key, msg, seed = nil, label = '')
    RSAESOAEP.new.encrypt(key, msg, seed, label)
  end

  def rsaes_oaep_decrypt(key, cipher, seed = nil, label = '')
    RSAESOAEP.new.decrypt(key, cipher, seed, label)
  end


  class RSAESOAEP
    include DataConversion
    include CryptographicPrimitive

    def initialize(digest = Digest::SHA1)
      @hlen = Hash.size(digest)
      @encryption_encoder = EncryptionEncoding::EMEOAEP.new(digest)
    end

    def encrypt(key, msg, seed = nil, label = '')
      k = key.modbytes
      if msg.size > k - 2 * @hlen - 2
        raise ArgumentError, "message too long"
      end
      em = @encryption_encoder.encode(msg, k, seed, label)
      m = os2ip(em)
      c = rsaep(key, m)
      i2osp(c, k)
    end

    def decrypt(key, cipher, label = '')
      k = key.modbytes
      if cipher.size != k
        raise ArgumentError, "decryption error"
      end
      if k < 2 * @hlen + 2
        raise ArgumentError, "decryption error"
      end
      c = os2ip(cipher)
      m = rsadp(key, c)
      em = i2osp(m, k)
      @encryption_encoder.decode(em, k, label)
    end
  end
end


# 7.1.1 1.b and 7.1.2 3 Encoding methods for encryption
module EncryptionEncoding
module_function

  def eme_oaep_encode(msg, embits, seed = nil)
    EMEOAEP.new.encode(msg, embits, seed)
  end

  def eme_oaep_decode(msg, em, embits)
    EMEOAEP.new.decode(msg, em, embits)
  end


  class EMEOAEP
    include Util

    def initialize(digest = Digest::SHA1, mgf = nil)
      @digest = digest
      @hlen = Hash.size(@digest)
      @mgf = mgf || MaskGeneration::MGF1.new(@digest)
    end

    def encode(msg, embytes, seed = nil, label = '')
      lhash = dohash(label)
      ps = "\x00" * (embytes - msg.size - 2 * @hlen - 2)
      db = lhash + ps + "\x01" + msg
      seed ||= OpenSSL::Random.random_bytes(@hlen)
      dbmask = @mgf.generate(seed, embytes - @hlen - 1)
      maskeddb = xor(db, dbmask)
      seedmask = @mgf.generate(maskeddb, @hlen)
      maskedseed = xor(seed, seedmask)
      "\x00" + maskedseed + maskeddb
    end

    def decode(em, embytes, label = '')
      lhash = dohash(label)
      y = em[0]
      maskedseed = em[1, @hlen]
      maskeddb = em[1 + @hlen, embytes - @hlen - 1]
      seedmask = @mgf.generate(maskeddb, @hlen)
      seed = xor(maskedseed, seedmask)
      dbmask = @mgf.generate(seed, embytes - @hlen - 1)
      db = xor(maskeddb, dbmask)
      lhashdash = db[0, @hlen]
      if lhashdash != lhash
        raise ArgumentError, "decryption error"
      end
      psm = db[@hlen, embytes - 2 * @hlen - 1]
      if /\A(\x00*)\x01([\x00-\xff]*)\z/ =~ psm
        ps, m = $1, $2
      else
        raise ArgumentError, "decryption error"
      end
      m
    end

  private

    def dohash(msg)
      @digest.digest(msg)
    end
  end
end


# 8 Signature schemes
module SignatureScheme
module_function

  def rsassa_pss_sign(key, msg)
    RSASSAPSS.new.sign(key, msg)
  end

  def rsassa_pss_verify(key, msg, sig)
    RSASSAPSS.new.verify(key, msg, sig)
  end

  def rsassa_pss_sign_hash(key, hash)
    RSASSAPSS.new.sign_hash(key, hash)
  end

  def rsassa_pss_verify_hash(key, hash, sig)
    RSASSAPSS.new.verify_hash(key, hash, sig)
  end

  def rsassa_pkcs1v1_5_sign(key, msg)
    RSASSAPKCS1v1_5.new.sign(key, msg)
  end

  def rsassa_pkcs1v1_5_verify(key, msg, sig)
    RSASSAPKCS1v1_5.new.verify(key, msg, sig)
  end

  def rsassa_pkcs1v1_5_sign_hash(key, hash)
    RSASSAPKCS1v1_5.new.sign_hash(key, hash)
  end

  def rsassa_pkcs1v1_5_verify_hash(key, hash, sig)
    RSASSAPKCS1v1_5.new.verify_hash(key, hash, sig)
  end


  class RSASSAPSS
    include Util
    include DataConversion
    include CryptographicPrimitive

    def initialize(digest = Digest::SHA1, slen = 20, mgf = nil)
      @signature_encoder = SignatureEncoding::EMSAPSS.new(digest, slen, mgf)
    end

    def sign(key, msg, salt = nil)
      modbits = key.modbits
      em = @signature_encoder.encode(msg, modbits - 1, salt)
      sign_em(key, em, modbits)
    end

    def sign_hash(key, hash, salt = nil)
      modbits = key.modbits
      em = @signature_encoder.encode_hash(hash, modbits - 1, salt)
      sign_em(key, em, modbits)
    end

    def verify(key, msg, sig)
      modbits = key.modbits
      em = decode_em(key, sig, modbits)
      @signature_encoder.verify(msg, em, modbits - 1)
    end

    def verify_hash(key, hash, sig)
      modbits = key.modbits
      em = decode_em(key, sig, modbits)
      @signature_encoder.verify_hash(hash, em, modbits - 1)
    end

  private

    def sign_em(key, em, modbits)
      m = os2ip(em)
      s = rsasp1(key, m)
      s = i2osp(s, divceil(modbits, 8))
      s
    end

    def decode_em(key, sig, modbits)
      if sig.size != divceil(modbits - 1, 8)
        raise ArgumentError, "invalid signature"
      end
      s = os2ip(sig)
      m = rsavp1(key, s)
      emlen = divceil(modbits - 1, 8)
      i2osp(m, emlen)
    end
  end


  class RSASSAPKCS1v1_5
    include DataConversion
    include CryptographicPrimitive

    def initialize(digest = Digest::SHA1)
      @signature_encoder = SignatureEncoding::EMSAPKCS1v1_5.new(digest)
    end

    def sign(key, msg)
      k = key.modbytes
      em = @signature_encoder.encode(msg, k)
      sign_em(key, em, k)
    end

    def sign_hash(key, hash)
      k = key.modbytes
      em = @signature_encoder.encode_hash(hash, k)
      sign_em(key, em, k)
    end

    def verify(key, msg, sig)
      k = key.modbytes
      em = decode_em(key, sig, k)
      emdash = @signature_encoder.encode(msg, k)
      unless em == emdash
        raise ArgumentError, "invalid signature"
      end
      true
    end

    def verify_hash(key, hash, sig)
      k = key.modbytes
      em = decode_em(key, sig, k)
      emdash = @signature_encoder.encode_hash(hash, k)
      unless em == emdash
        raise ArgumentError, "invalid signature"
      end
      true
    end

  private

    def sign_em(key, em, k)
      m = os2ip(em)
      s = rsasp1(key, m)
      i2osp(s, k)
    end

    def decode_em(key, sig, k)
      if sig.size != k
        raise ArgumentError, "invalid signature"
      end
      s = os2ip(sig)
      m = rsavp1(key, s)
      i2osp(m, k)
    end
  end
end


# 9 Encoding methods for signatures with appendix
module SignatureEncoding
module_function

  def emsa_pss_encode(msg, embits, salt = nil)
    EMSAPSS.new.encode(msg, embits, salt)
  end

  def emsa_pss_verify(msg, em, embits)
    EMSAPSS.new.verify(msg, em, embits)
  end

  def emsa_pkcs1_v1_5_encode(msg, emlen)
    EMSAPKCS1v1_5.new.encode(msg, emlen)
  end


  class EMSAPSS
    include Util

    def initialize(digest = Digest::SHA1, slen = 20, mgf = nil)
      @digest = digest
      @slen = slen
      @hlen = Hash.size(@digest)
      @mgf = mgf || MaskGeneration::MGF1.new(@digest)
    end

    def encode(msg, embits, salt = nil)
      mhash = dohash(msg)
      encode_hash(mhash, embits, salt)
    end

    def encode_hash(mhash, embits, salt = nil)
      emlen = divceil(embits, 8)
      if emlen < @hlen + @slen + 2
        raise ArgumentError, "encoding error"
      end
      salt ||= OpenSSL::Random.random_bytes(@slen)
      mdash = "\x00" * 8 + mhash + salt
      h = dohash(mdash)
      ps = "\x00" * (emlen - @slen - @hlen - 2)
      db = ps + "\x01" + salt
      dbmask = @mgf.generate(h, emlen - @hlen - 1)
      maskeddb = xor(db, dbmask)
      ary = maskeddb.unpack('C*')
      ary[0] &= (0xff >> (8 * emlen - embits))
      maskeddb = ary.pack('C*')
      em = maskeddb + h + "\xbc"
      em
    end

    def verify(msg, em, embits)
      mhash = dohash(msg)
      verify_hash(mhash, em, embits)
    end

    def verify_hash(mhash, em, embits)
      emlen = divceil(embits, 8)
      if emlen < @hlen + @slen + 2
        raise ArgumentError, "inconsistent"
      end
      if em[-1] != 0xbc
        raise ArgumentError, "inconsistent"
      end
      maskeddb = em[0, emlen - @hlen - 1]
      h = em[emlen - @hlen - 1, @hlen]
      if maskeddb[0] & (0xff >> (8 * emlen - embits)) != maskeddb[0]
        raise ArgumentError, "inconsistent"
      end
      dbmask = @mgf.generate(h, emlen - @hlen - 1)
      db = xor(maskeddb, dbmask)
      db[0] &= (0xff >> (8 * emlen - embits))
      if /\A\x00+\z/ !~ db[0, emlen - @hlen - @slen - 2]
        raise ArgumentError, "inconsistent"
      end
      if db[emlen - @hlen - @slen - 2] != 0x01
        raise ArgumentError, "inconsistent"
      end
      salt = db[db.size - @slen, @slen]
      mdash = "\x00" * 8 + mhash + salt
      hdash = dohash(mdash)
      if h != hdash
        raise ArgumentError, "inconsistent"
      end
      true
    end

  private

    def dohash(msg)
      @digest.digest(msg)
    end
  end


  class EMSAPKCS1v1_5
    def initialize(digest = Digest::SHA1)
      @digest = digest
    end

    def encode(msg, emlen)
      h = dohash(msg)
      encode_hash(h, emlen)
    end

    def encode_hash(h, emlen)
      t = Hash.asnoid(@digest) + h
      if emlen < t.size + 11
        raise ArgumentError, "intended encoded message length too short"
      end
      ps = "\xff" * (emlen - t.size - 3)
      "\x00\x01" + ps + "\x00" + t
    end

  private

    def dohash(msg)
      @digest.digest(msg)
    end
  end
end


# B.1 Hash functions
module Hash
  ALGORITHMS = {
    # MD5: 1.2.840.113549.2.5
    Digest::MD5 => [16, [0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48,
      0x86, 0xF7, 0x0D, 0x02, 0x05, 0x00, 0x04, 0x10]],
    # SHA-1: 1.3.14.3.2.26
    Digest::SHA1 => [20, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E, 0x03,
      0x02, 0x1A, 0x05, 0x00, 0x04, 0x14]],
    # SHA256: 2.16.840.1.101.3.4.2.1
    Digest::SHA256 => [32, [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]],
    # SHA384: 2.16.840.1.101.3.4.2.2
    Digest::SHA384 => [48, [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]],
    # SHA512: 2.16.840.1.101.3.4.2.3
    Digest::SHA512 => [64, [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
      0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]],
  }

module_function

  def asnoid(digest)
    unless ALGORITHMS.key?(digest)
      raise ArgumentError, "unknown digest: #{digest}"
    end
    ALGORITHMS[digest][1].pack("C*")
  end

  def size(digest)
    unless ALGORITHMS.key?(digest)
      raise ArgumentError, "unknown digest: #{digest}"
    end
    ALGORITHMS[digest][0]
  end
end


# B.2 Mask generation functions
module MaskGeneration
module_function

  def mgf1(seed, masklen)
    MGF1.new.generate(seed, masklen)
  end


  class MGF1
    include Util
    include DataConversion

    def initialize(digest = Digest::SHA1)
      @digest = digest
      @hlen = Hash.size(@digest)
    end

    def generate(seed, masklen)
      if masklen > (2 << 31) * @hlen
        raise ArgumentError, "mask too long"
      end
      t = ""
      divceil(masklen, @hlen).times do |counter|
        t += dohash(seed + i2osp(counter, 4))
      end
      t[0, masklen]
    end

  private

    def dohash(msg)
      @digest.digest(msg)
    end
  end
end


end


if $0 == __FILE__
  pkeyfile = ARGV.shift or raise "pkey file not given"
  osslkey = OpenSSL::PKey::RSA.new(File.read(pkeyfile))
  n = osslkey.n.to_i
  e = osslkey.e.to_i
  d = osslkey.d.to_i
  p = osslkey.p.to_i
  q = osslkey.q.to_i
  dp = osslkey.dmp1.to_i
  dq = osslkey.dmq1.to_i
  qinv = osslkey.iqmp.to_i

  require 'pgp/hexdump'

  rsapss = PKCS1::SignatureScheme::RSASSAPSS.new(Digest::SHA256, 0, PKCS1::MaskGeneration::MGF1.new(Digest::SHA1))
  key = PKCS1::Key::RSA.new(n, e, d)
  puts PGP::HexDump.encode(rsapss.sign(key, "hello world"))
  exit

  puts

  key2 = PKCS1::Key::RSACRTPrivateKey.new(n, d, p, q, dp, dq, qinv)
  puts PGP::HexDump.encode(rsapss.sign_hash(key2, "hello world", "\0"*8))

  p PKCS1::DataConversion.i2osp(65537, 3)
  p PKCS1::DataConversion.os2ip(PKCS1::DataConversion.i2osp(65537, 3))

  key = PKCS1::Key::RSA.new(osslkey.n.to_i, osslkey.e.to_i, osslkey.d.to_i)
  msg = "hello"
  p PKCS1::DataConversion.i2osp(PKCS1::CryptographicPrimitive.rsadp(key, PKCS1::CryptographicPrimitive.rsaep(key, PKCS1::DataConversion.os2ip(msg))), msg.size)
  p PKCS1::DataConversion.i2osp(PKCS1::CryptographicPrimitive.rsavp1(key, PKCS1::CryptographicPrimitive.rsasp1(key, PKCS1::DataConversion.os2ip(msg))), msg.size)

  p PKCS1::MaskGeneration.mgf1("abc", 20)
  p PKCS1::MaskGeneration.mgf1("abcd", 20)

  pss = PKCS1::SignatureEncoding::EMSAPSS.new(Digest::SHA1, 8)
  p pss.encode("hello", 1023)
  p pss.verify("hello", pss.encode("hello", 1023), 1023)

  rsapss = PKCS1::SignatureScheme::RSASSAPSS.new(Digest::SHA1, 0)
  p rsapss.sign(key, "hello")
  p rsapss.verify(key, "hello", rsapss.sign(key, "hello"))

  msg = "foo\nbar" * 1024
  hash = Digest::SHA1.digest(msg)
  p rsapss.verify_hash(key, hash, rsapss.sign_hash(key, hash))
  p rsapss.verify(key, msg, rsapss.sign_hash(key, hash))
  p rsapss.verify_hash(key, hash, rsapss.sign(key, msg))

  exit

  p PKCS1::SignatureEncoding.emsa_pkcs1_v1_5_encode("foo", 128)
  rsapkcs1 = PKCS1::SignatureScheme::RSASSAPKCS1v1_5.new(Digest::SHA1)
  p rsapkcs1.sign(key, "hello")
  p rsapkcs1.verify(key, "hello", rsapkcs1.sign(key, "hello"))
  p osslkey.sign(OpenSSL::Digest::SHA1.new, "hello")
  p osslkey.verify(OpenSSL::Digest::SHA1.new, rsapkcs1.sign(key, "hello"), "hello")

  rsaoaep = PKCS1::EncryptionScheme::RSAESOAEP.new(Digest::SHA1)
  msg = "hello"
  p rsaoaep.encrypt(key, msg)
  p osslkey.public_encrypt(msg, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  p osslkey.private_decrypt(rsaoaep.encrypt(key, msg), OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING) == msg
  p rsaoaep.decrypt(key, rsaoaep.encrypt(key, msg)) == msg
end
