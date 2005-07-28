# Copyright 2005  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
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


require 'test/unit'
require 'pkcs1'


module PKCS1


class TestPSS < Test::Unit::TestCase
  def setup
    @content = DATA.read
  end

  def test_pss
    buf = nil
    key_create = check = false
    section = title = nil
    key = nil
    n = e = d = p = q = dp = dq = qinv = msg = salt = sig = nil
    @content.each do |line|
      case line
      when /^# Example/
        section = line.chomp
      when /Signature Example/
        title = section + " #{line.chomp}"
      when /^# RSA modulus n/
        n = buf = []
      when /^# RSA public exponent e/
        e = buf = []
      when /^# RSA private exponent d/
        d = buf = []
      when /^# Prime p/
        p = buf = []
      when /^# Prime q/
        q = buf = []
      when /^# p's CRT exponent dP/
        dp = buf = []
      when /^# q's CRT exponent dQ/
        dq = buf = []
      when /^# CRT coefficient qInv/
        qinv = buf = []
        key_create = true
      when /^# Message to be signed/
        msg = buf = []
      when /^# Salt/
        salt = buf = []
      when /^# Signature/
        sig = buf = []
        check = true
      when /^(?:[0-9a-z]{2})(?: [0-9a-z]{2})*/
        buf << line.chomp
      when /^\s*$/
        if key_create
          key = create_key(n, e, p, q, dp, dq, qinv)
          key_create = false
        end
        if check
          do_check(title, key, msg, salt, sig)
          check = false
        end
      end
    end
  end

  def create_key(n, e, p, q, dp, dq, qinv)
    n = hex2i(n)
    e = hex2i(e)
    p = hex2i(p)
    q = hex2i(q)
    dp = hex2i(dp)
    dq = hex2i(dq)
    qinv = hex2i(qinv)
    PKCS1::Key::RSACRT.new(n, e, p, q, dp, dq, qinv)
  end

  def do_check(title, key, msg, salt, sig)
    puts title
    msg = hex2b(msg)
    salt = hex2b(salt)
    sig = hex2b(sig)
    signer = PKCS1::SignatureScheme::RSASSAPSS.new(Digest::SHA1, salt.size)
    mysig = signer.sign(key, msg, salt)
    assert_equal(sig, mysig, title)
  end

  def hex2b(hexdump)
    hexdump.collect { |line|
      line.chomp!
      line.gsub!(/\s*/, '')
      line.gsub(/((?:[0-9a-fA-F]{2})+)/n) {
        [$1].pack('H*')
      }
    }.join
  end

  def hex2i(hexdump)
    PKCS1::DataConversion.os2ip(hex2b(hexdump))
  end
end


end


# Following is the test vectors of PKCS#1 v2.1 RSA-PSS.  The test vectors is
# published and distributed by RSA.  See PKCS#1 home page.

__END__
# ===========================
# TEST VECTORS FOR RSASSA-PSS
# ===========================
# 
# This file contains test vectors for the
# RSASSA-PSS signature scheme with appendix as
# defined in PKCS #1 v2.1. 10 RSA keys of
# different sizes have been generated. For each
# key, 6 random messages of length between 1
# and 256 octets have been RSASSA-PSS signed
# via a random salt of length 20 octets. 
#
# The underlying hash function in the EMSA-PSS
# encoding method is SHA-1; the mask generation
# function is MGF1 with SHA-1 as specified in 
# PKCS #1 v2.1.
# 
# Integers are represented by strings of octets
# with the leftmost octet being the most 
# significant octet. For example, 
#
#           9,202,000 = (0x)8c 69 50. 
#
# Key lengths:
# 
# Key  1: 1024 bits
# Key  2: 1025 bits
# Key  3: 1026 bits
# Key  4: 1027 bits
# Key  5: 1028 bits
# Key  6: 1029 bits
# Key  7: 1030 bits
# Key  8: 1031 bits
# Key  9: 1536 bits
# Key 10: 2048 bits
#
# =============================================

# ==================================
# Example 1: A 1024-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
a5 6e 4a 0e 70 10 17 58 9a 51 87 dc 7e a8 41 d1 
56 f2 ec 0e 36 ad 52 a4 4d fe b1 e6 1f 7a d9 91 
d8 c5 10 56 ff ed b1 62 b4 c0 f2 83 a1 2a 88 a3 
94 df f5 26 ab 72 91 cb b3 07 ce ab fc e0 b1 df 
d5 cd 95 08 09 6d 5b 2b 8b 6d f5 d6 71 ef 63 77 
c0 92 1c b2 3c 27 0a 70 e2 59 8e 6f f8 9d 19 f1 
05 ac c2 d3 f0 cb 35 f2 92 80 e1 38 6b 6f 64 c4 
ef 22 e1 e1 f2 0d 0c e8 cf fb 22 49 bd 9a 21 37 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
33 a5 04 2a 90 b2 7d 4f 54 51 ca 9b bb d0 b4 47 
71 a1 01 af 88 43 40 ae f9 88 5f 2a 4b be 92 e8 
94 a7 24 ac 3c 56 8c 8f 97 85 3a d0 7c 02 66 c8 
c6 a3 ca 09 29 f1 e8 f1 12 31 88 44 29 fc 4d 9a 
e5 5f ee 89 6a 10 ce 70 7c 3e d7 e7 34 e4 47 27 
a3 95 74 50 1a 53 26 83 10 9c 2a ba ca ba 28 3c 
31 b4 bd 2f 53 c3 ee 37 e3 52 ce e3 4f 9e 50 3b 
d8 0c 06 22 ad 79 c6 dc ee 88 35 47 c6 a3 b3 25 

# Prime p: 
e7 e8 94 27 20 a8 77 51 72 73 a3 56 05 3e a2 a1 
bc 0c 94 aa 72 d5 5c 6e 86 29 6b 2d fc 96 79 48 
c0 a7 2c bc cc a7 ea cb 35 70 6e 09 a1 df 55 a1 
53 5b d9 b3 cc 34 16 0b 3b 6d cd 3e da 8e 64 43 

# Prime q: 
b6 9d ca 1c f7 d4 d7 ec 81 e7 5b 90 fc ca 87 4a 
bc de 12 3f d2 70 01 80 aa 90 47 9b 6e 48 de 8d 
67 ed 24 f9 f1 9d 85 ba 27 58 74 f5 42 cd 20 dc 
72 3e 69 63 36 4a 1f 94 25 45 2b 26 9a 67 99 fd 

# p's CRT exponent dP: 
28 fa 13 93 86 55 be 1f 8a 15 9c ba ca 5a 72 ea 
19 0c 30 08 9e 19 cd 27 4a 55 6f 36 c4 f6 e1 9f 
55 4b 34 c0 77 79 04 27 bb dd 8d d3 ed e2 44 83 
28 f3 85 d8 1b 30 e8 e4 3b 2f ff a0 27 86 19 79 

# q's CRT exponent dQ: 
1a 8b 38 f3 98 fa 71 20 49 89 8d 7f b7 9e e0 a7 
76 68 79 12 99 cd fa 09 ef c0 e5 07 ac b2 1e d7 
43 01 ef 5b fd 48 be 45 5e ae b6 e1 67 82 55 82 
75 80 a8 e4 e8 e1 41 51 d1 51 0a 82 a3 f2 e7 29 

# CRT coefficient qInv: 
27 15 6a ba 41 26 d2 4a 81 f3 a5 28 cb fb 27 f5 
68 86 f8 40 a9 f6 e8 6e 17 a4 4b 94 fe 93 19 58 
4b 8e 22 fd de 1e 5a 2e 3b d8 aa 5b a8 d8 58 41 
94 eb 21 90 ac f8 32 b8 47 f1 3a 3d 24 a7 9f 4d 

# --------------------------------
# RSASSA-PSS Signature Example 1.1
# --------------------------------

# Message to be signed:
cd c8 7d a2 23 d7 86 df 3b 45 e0 bb bc 72 13 26 
d1 ee 2a f8 06 cc 31 54 75 cc 6f 0d 9c 66 e1 b6 
23 71 d4 5c e2 39 2e 1a c9 28 44 c3 10 10 2f 15 
6a 0d 8d 52 c1 f4 c4 0b a3 aa 65 09 57 86 cb 76 
97 57 a6 56 3b a9 58 fe d0 bc c9 84 e8 b5 17 a3 
d5 f5 15 b2 3b 8a 41 e7 4a a8 67 69 3f 90 df b0 
61 a6 e8 6d fa ae e6 44 72 c0 0e 5f 20 94 57 29 
cb eb e7 7f 06 ce 78 e0 8f 40 98 fb a4 1f 9d 61 
93 c0 31 7e 8b 60 d4 b6 08 4a cb 42 d2 9e 38 08 
a3 bc 37 2d 85 e3 31 17 0f cb f7 cc 72 d0 b7 1c 
29 66 48 b3 a4 d1 0f 41 62 95 d0 80 7a a6 25 ca 
b2 74 4f d9 ea 8f d2 23 c4 25 37 02 98 28 bd 16 
be 02 54 6f 13 0f d2 e3 3b 93 6d 26 76 e0 8a ed 
1b 73 31 8b 75 0a 01 67 d0 

# Salt:
de e9 59 c7 e0 64 11 36 14 20 ff 80 18 5e d5 7f 
3e 67 76 af 

# Signature:
90 74 30 8f b5 98 e9 70 1b 22 94 38 8e 52 f9 71 
fa ac 2b 60 a5 14 5a f1 85 df 52 87 b5 ed 28 87 
e5 7c e7 fd 44 dc 86 34 e4 07 c8 e0 e4 36 0b c2 
26 f3 ec 22 7f 9d 9e 54 63 8e 8d 31 f5 05 12 15 
df 6e bb 9c 2f 95 79 aa 77 59 8a 38 f9 14 b5 b9 
c1 bd 83 c4 e2 f9 f3 82 a0 d0 aa 35 42 ff ee 65 
98 4a 60 1b c6 9e b2 8d eb 27 dc a1 2c 82 c2 d4 
c3 f6 6c d5 00 f1 ff 2b 99 4d 8a 4e 30 cb b3 3c 

# --------------------------------
# RSASSA-PSS Signature Example 1.2
# --------------------------------

# Message to be signed:
85 13 84 cd fe 81 9c 22 ed 6c 4c cb 30 da eb 5c 
f0 59 bc 8e 11 66 b7 e3 53 0c 4c 23 3e 2b 5f 8f 
71 a1 cc a5 82 d4 3e cc 72 b1 bc a1 6d fc 70 13 
22 6b 9e 

# Salt:
ef 28 69 fa 40 c3 46 cb 18 3d ab 3d 7b ff c9 8f 
d5 6d f4 2d 

# Signature:
3e f7 f4 6e 83 1b f9 2b 32 27 41 42 a5 85 ff ce 
fb dc a7 b3 2a e9 0d 10 fb 0f 0c 72 99 84 f0 4e 
f2 9a 9d f0 78 07 75 ce 43 73 9b 97 83 83 90 db 
0a 55 05 e6 3d e9 27 02 8d 9d 29 b2 19 ca 2c 45 
17 83 25 58 a5 5d 69 4a 6d 25 b9 da b6 60 03 c4 
cc cd 90 78 02 19 3b e5 17 0d 26 14 7d 37 b9 35 
90 24 1b e5 1c 25 05 5f 47 ef 62 75 2c fb e2 14 
18 fa fe 98 c2 2c 4d 4d 47 72 4f db 56 69 e8 43 

# --------------------------------
# RSASSA-PSS Signature Example 1.3
# --------------------------------

# Message to be signed:
a4 b1 59 94 17 61 c4 0c 6a 82 f2 b8 0d 1b 94 f5 
aa 26 54 fd 17 e1 2d 58 88 64 67 9b 54 cd 04 ef 
8b d0 30 12 be 8d c3 7f 4b 83 af 79 63 fa ff 0d 
fa 22 54 77 43 7c 48 01 7f f2 be 81 91 cf 39 55 
fc 07 35 6e ab 3f 32 2f 7f 62 0e 21 d2 54 e5 db 
43 24 27 9f e0 67 e0 91 0e 2e 81 ca 2c ab 31 c7 
45 e6 7a 54 05 8e b5 0d 99 3c db 9e d0 b4 d0 29 
c0 6d 21 a9 4c a6 61 c3 ce 27 fa e1 d6 cb 20 f4 
56 4d 66 ce 47 67 58 3d 0e 5f 06 02 15 b5 90 17 
be 85 ea 84 89 39 12 7b d8 c9 c4 d4 7b 51 05 6c 
03 1c f3 36 f1 7c 99 80 f3 b8 f5 b9 b6 87 8e 8b 
79 7a a4 3b 88 26 84 33 3e 17 89 3f e9 ca a6 aa 
29 9f 7e d1 a1 8e e2 c5 48 64 b7 b2 b9 9b 72 61 
8f b0 25 74 d1 39 ef 50 f0 19 c9 ee f4 16 97 13 
38 e7 d4 70 

# Salt:
71 0b 9c 47 47 d8 00 d4 de 87 f1 2a fd ce 6d f1 
81 07 cc 77 

# Signature:
66 60 26 fb a7 1b d3 e7 cf 13 15 7c c2 c5 1a 8e 
4a a6 84 af 97 78 f9 18 49 f3 43 35 d1 41 c0 01 
54 c4 19 76 21 f9 62 4a 67 5b 5a bc 22 ee 7d 5b 
aa ff aa e1 c9 ba ca 2c c3 73 b3 f3 3e 78 e6 14 
3c 39 5a 91 aa 7f ac a6 64 eb 73 3a fd 14 d8 82 
72 59 d9 9a 75 50 fa ca 50 1e f2 b0 4e 33 c2 3a 
a5 1f 4b 9e 82 82 ef db 72 8c c0 ab 09 40 5a 91 
60 7c 63 69 96 1b c8 27 0d 2d 4f 39 fc e6 12 b1 

# --------------------------------
# RSASSA-PSS Signature Example 1.4
# --------------------------------

# Message to be signed:
bc 65 67 47 fa 9e af b3 f0 

# Salt:
05 6f 00 98 5d e1 4d 8e f5 ce a9 e8 2f 8c 27 be 
f7 20 33 5e 

# Signature:
46 09 79 3b 23 e9 d0 93 62 dc 21 bb 47 da 0b 4f 
3a 76 22 64 9a 47 d4 64 01 9b 9a ea fe 53 35 9c 
17 8c 91 cd 58 ba 6b cb 78 be 03 46 a7 bc 63 7f 
4b 87 3d 4b ab 38 ee 66 1f 19 96 34 c5 47 a1 ad 
84 42 e0 3d a0 15 b1 36 e5 43 f7 ab 07 c0 c1 3e 
42 25 b8 de 8c ce 25 d4 f6 eb 84 00 f8 1f 7e 18 
33 b7 ee 6e 33 4d 37 09 64 ca 79 fd b8 72 b4 d7 
52 23 b5 ee b0 81 01 59 1f b5 32 d1 55 a6 de 87 

# --------------------------------
# RSASSA-PSS Signature Example 1.5
# --------------------------------

# Message to be signed:
b4 55 81 54 7e 54 27 77 0c 76 8e 8b 82 b7 55 64 
e0 ea 4e 9c 32 59 4d 6b ff 70 65 44 de 0a 87 76 
c7 a8 0b 45 76 55 0e ee 1b 2a ca bc 7e 8b 7d 3e 
f7 bb 5b 03 e4 62 c1 10 47 ea dd 00 62 9a e5 75 
48 0a c1 47 0f e0 46 f1 3a 2b f5 af 17 92 1d c4 
b0 aa 8b 02 be e6 33 49 11 65 1d 7f 85 25 d1 0f 
32 b5 1d 33 be 52 0d 3d df 5a 70 99 55 a3 df e7 
82 83 b9 e0 ab 54 04 6d 15 0c 17 7f 03 7f dc cc 
5b e4 ea 5f 68 b5 e5 a3 8c 9d 7e dc cc c4 97 5f 
45 5a 69 09 b4 

# Salt:
80 e7 0f f8 6a 08 de 3e c6 09 72 b3 9b 4f bf dc 
ea 67 ae 8e 

# Signature:
1d 2a ad 22 1c a4 d3 1d df 13 50 92 39 01 93 98 
e3 d1 4b 32 dc 34 dc 5a f4 ae ae a3 c0 95 af 73 
47 9c f0 a4 5e 56 29 63 5a 53 a0 18 37 76 15 b1 
6c b9 b1 3b 3e 09 d6 71 eb 71 e3 87 b8 54 5c 59 
60 da 5a 64 77 6e 76 8e 82 b2 c9 35 83 bf 10 4c 
3f db 23 51 2b 7b 4e 89 f6 33 dd 00 63 a5 30 db 
45 24 b0 1c 3f 38 4c 09 31 0e 31 5a 79 dc d3 d6 
84 02 2a 7f 31 c8 65 a6 64 e3 16 97 8b 75 9f ad 

# --------------------------------
# RSASSA-PSS Signature Example 1.6
# --------------------------------

# Message to be signed:
10 aa e9 a0 ab 0b 59 5d 08 41 20 7b 70 0d 48 d7 
5f ae dd e3 b7 75 cd 6b 4c c8 8a e0 6e 46 94 ec 
74 ba 18 f8 52 0d 4f 5e a6 9c bb e7 cc 2b eb a4 
3e fd c1 02 15 ac 4e b3 2d c3 02 a1 f5 3d c6 c4 
35 22 67 e7 93 6c fe bf 7c 8d 67 03 57 84 a3 90 
9f a8 59 c7 b7 b5 9b 8e 39 c5 c2 34 9f 18 86 b7 
05 a3 02 67 d4 02 f7 48 6a b4 f5 8c ad 5d 69 ad 
b1 7a b8 cd 0c e1 ca f5 02 5a f4 ae 24 b1 fb 87 
94 c6 07 0c c0 9a 51 e2 f9 91 13 11 e3 87 7d 00 
44 c7 1c 57 a9 93 39 50 08 80 6b 72 3a c3 83 73 
d3 95 48 18 18 52 8c 1e 70 53 73 92 82 05 35 29 
51 0e 93 5c d0 fa 77 b8 fa 53 cc 2d 47 4b d4 fb 
3c c5 c6 72 d6 ff dc 90 a0 0f 98 48 71 2c 4b cf 
e4 6c 60 57 36 59 b1 1e 64 57 e8 61 f0 f6 04 b6 
13 8d 14 4f 8c e4 e2 da 73 

# Salt:
a8 ab 69 dd 80 1f 00 74 c2 a1 fc 60 64 98 36 c6 
16 d9 96 81 

# Signature:
2a 34 f6 12 5e 1f 6b 0b f9 71 e8 4f bd 41 c6 32 
be 8f 2c 2a ce 7d e8 b6 92 6e 31 ff 93 e9 af 98 
7f bc 06 e5 1e 9b e1 4f 51 98 f9 1f 3f 95 3b d6 
7d a6 0a 9d f5 97 64 c3 dc 0f e0 8e 1c be f0 b7 
5f 86 8d 10 ad 3f ba 74 9f ef 59 fb 6d ac 46 a0 
d6 e5 04 36 93 31 58 6f 58 e4 62 8f 39 aa 27 89 
82 54 3b c0 ee b5 37 dc 61 95 80 19 b3 94 fb 27 
3f 21 58 58 a0 a0 1a c4 d6 50 b9 55 c6 7f 4c 58 

# =============================================

# ==================================
# Example 2: A 1025-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
01 d4 0c 1b cf 97 a6 8a e7 cd bd 8a 7b f3 e3 4f 
a1 9d cc a4 ef 75 a4 74 54 37 5f 94 51 4d 88 fe 
d0 06 fb 82 9f 84 19 ff 87 d6 31 5d a6 8a 1f f3 
a0 93 8e 9a bb 34 64 01 1c 30 3a d9 91 99 cf 0c 
7c 7a 8b 47 7d ce 82 9e 88 44 f6 25 b1 15 e5 e9 
c4 a5 9c f8 f8 11 3b 68 34 33 6a 2f d2 68 9b 47 
2c bb 5e 5c ab e6 74 35 0c 59 b6 c1 7e 17 68 74 
fb 42 f8 fc 3d 17 6a 01 7e dc 61 fd 32 6c 4b 33 
c9 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
02 7d 14 7e 46 73 05 73 77 fd 1e a2 01 56 57 72 
17 6a 7d c3 83 58 d3 76 04 56 85 a2 e7 87 c2 3c 
15 57 6b c1 6b 9f 44 44 02 d6 bf c5 d9 8a 3e 88 
ea 13 ef 67 c3 53 ec a0 c0 dd ba 92 55 bd 7b 8b 
b5 0a 64 4a fd fd 1d d5 16 95 b2 52 d2 2e 73 18 
d1 b6 68 7a 1c 10 ff 75 54 5f 3d b0 fe 60 2d 5f 
2b 7f 29 4e 36 01 ea b7 b9 d1 ce cd 76 7f 64 69 
2e 3e 53 6c a2 84 6c b0 c2 dd 48 6a 39 fa 75 b1 

# Prime p: 
01 66 01 e9 26 a0 f8 c9 e2 6e ca b7 69 ea 65 a5 
e7 c5 2c c9 e0 80 ef 51 94 57 c6 44 da 68 91 c5 
a1 04 d3 ea 79 55 92 9a 22 e7 c6 8a 7a f9 fc ad 
77 7c 3c cc 2b 9e 3d 36 50 bc e4 04 39 9b 7e 59 
d1 

# Prime q: 
01 4e af a1 d4 d0 18 4d a7 e3 1f 87 7d 12 81 dd 
da 62 56 64 86 9e 83 79 e6 7a d3 b7 5e ae 74 a5 
80 e9 82 7a bd 6e b7 a0 02 cb 54 11 f5 26 67 97 
76 8f b8 e9 5a e4 0e 3e 8a 01 f3 5f f8 9e 56 c0 
79 

# p's CRT exponent dP: 
e2 47 cc e5 04 93 9b 8f 0a 36 09 0d e2 00 93 87 
55 e2 44 4b 29 53 9a 7d a7 a9 02 f6 05 68 35 c0 
db 7b 52 55 94 97 cf e2 c6 1a 80 86 d0 21 3c 47 
2c 78 85 18 00 b1 71 f6 40 1d e2 e9 c2 75 6f 31 

# q's CRT exponent dQ: 
b1 2f ba 75 78 55 e5 86 e4 6f 64 c3 8a 70 c6 8b 
3f 54 8d 93 d7 87 b3 99 99 9d 4c 8f 0b bd 25 81 
c2 1e 19 ed 00 18 a6 d5 d3 df 86 42 4b 3a bc ad 
40 19 9d 31 49 5b 61 30 9f 27 c1 bf 55 d4 87 c1 

# CRT coefficient qInv: 
56 4b 1e 1f a0 03 bd a9 1e 89 09 04 25 aa c0 5b 
91 da 9e e2 50 61 e7 62 8d 5f 51 30 4a 84 99 2f 
dc 33 76 2b d3 78 a5 9f 03 0a 33 4d 53 2b d0 da 
e8 f2 98 ea 9e d8 44 63 6a d5 fb 8c bd c0 3c ad 

# --------------------------------
# RSASSA-PSS Signature Example 2.1
# --------------------------------

# Message to be signed:
da ba 03 20 66 26 3f ae db 65 98 48 11 52 78 a5 
2c 44 fa a3 a7 6f 37 51 5e d3 36 32 10 72 c4 0a 
9d 9b 53 bc 05 01 40 78 ad f5 20 87 51 46 aa e7 
0f f0 60 22 6d cb 7b 1f 1f c2 7e 93 60 

# Salt:
57 bf 16 0b cb 02 bb 1d c7 28 0c f0 45 85 30 b7 
d2 83 2f f7 

# Signature:
01 4c 5b a5 33 83 28 cc c6 e7 a9 0b f1 c0 ab 3f 
d6 06 ff 47 96 d3 c1 2e 4b 63 9e d9 13 6a 5f ec 
6c 16 d8 88 4b dd 99 cf dc 52 14 56 b0 74 2b 73 
68 68 cf 90 de 09 9a db 8d 5f fd 1d ef f3 9b a4 
00 7a b7 46 ce fd b2 2d 7d f0 e2 25 f5 46 27 dc 
65 46 61 31 72 1b 90 af 44 53 63 a8 35 8b 9f 60 
76 42 f7 8f ab 0a b0 f4 3b 71 68 d6 4b ae 70 d8 
82 78 48 d8 ef 1e 42 1c 57 54 dd f4 2c 25 89 b5 
b3 

# --------------------------------
# RSASSA-PSS Signature Example 2.2
# --------------------------------

# Message to be signed:
e4 f8 60 1a 8a 6d a1 be 34 44 7c 09 59 c0 58 57 
0c 36 68 cf d5 1d d5 f9 cc d6 ad 44 11 fe 82 13 
48 6d 78 a6 c4 9f 93 ef c2 ca 22 88 ce bc 2b 9b 
60 bd 04 b1 e2 20 d8 6e 3d 48 48 d7 09 d0 32 d1 
e8 c6 a0 70 c6 af 9a 49 9f cf 95 35 4b 14 ba 61 
27 c7 39 de 1b b0 fd 16 43 1e 46 93 8a ec 0c f8 
ad 9e b7 2e 83 2a 70 35 de 9b 78 07 bd c0 ed 8b 
68 eb 0f 5a c2 21 6b e4 0c e9 20 c0 db 0e dd d3 
86 0e d7 88 ef ac ca ca 50 2d 8f 2b d6 d1 a7 c1 
f4 1f f4 6f 16 81 c8 f1 f8 18 e9 c4 f6 d9 1a 0c 
78 03 cc c6 3d 76 a6 54 4d 84 3e 08 4e 36 3b 8a 
cc 55 aa 53 17 33 ed b5 de e5 b5 19 6e 9f 03 e8 
b7 31 b3 77 64 28 d9 e4 57 fe 3f bc b3 db 72 74 
44 2d 78 58 90 e9 cb 08 54 b6 44 4d ac e7 91 d7 
27 3d e1 88 97 19 33 8a 77 fe 

# Salt:
7f 6d d3 59 e6 04 e6 08 70 e8 98 e4 7b 19 bf 2e 
5a 7b 2a 90 

# Signature:
01 09 91 65 6c ca 18 2b 7f 29 d2 db c0 07 e7 ae 
0f ec 15 8e b6 75 9c b9 c4 5c 5f f8 7c 76 35 dd 
46 d1 50 88 2f 4d e1 e9 ae 65 e7 f7 d9 01 8f 68 
36 95 4a 47 c0 a8 1a 8a 6b 6f 83 f2 94 4d 60 81 
b1 aa 7c 75 9b 25 4b 2c 34 b6 91 da 67 cc 02 26 
e2 0b 2f 18 b4 22 12 76 1d cd 4b 90 8a 62 b3 71 
b5 91 8c 57 42 af 4b 53 7e 29 69 17 67 4f b9 14 
19 47 61 62 1c c1 9a 41 f6 fb 95 3f bc bb 64 9d 
ea 

# --------------------------------
# RSASSA-PSS Signature Example 2.3
# --------------------------------

# Message to be signed:
52 a1 d9 6c 8a c3 9e 41 e4 55 80 98 01 b9 27 a5 
b4 45 c1 0d 90 2a 0d cd 38 50 d2 2a 66 d2 bb 07 
03 e6 7d 58 67 11 45 95 aa bf 5a 7a eb 5a 8f 87 
03 4b bb 30 e1 3c fd 48 17 a9 be 76 23 00 23 60 
6d 02 86 a3 fa f8 a4 d2 2b 72 8e c5 18 07 9f 9e 
64 52 6e 3a 0c c7 94 1a a3 38 c4 37 99 7c 68 0c 
ca c6 7c 66 bf a1 

# Salt:
fc a8 62 06 8b ce 22 46 72 4b 70 8a 05 19 da 17 
e6 48 68 8c 

# Signature:
00 7f 00 30 01 8f 53 cd c7 1f 23 d0 36 59 fd e5 
4d 42 41 f7 58 a7 50 b4 2f 18 5f 87 57 85 20 c3 
07 42 af d8 43 59 b6 e6 e8 d3 ed 95 9d c6 fe 48 
6b ed c8 e2 cf 00 1f 63 a7 ab e1 62 56 a1 b8 4d 
f0 d2 49 fc 05 d3 19 4c e5 f0 91 27 42 db bf 80 
dd 17 4f 6c 51 f6 ba d7 f1 6c f3 36 4e ba 09 5a 
06 26 7d c3 79 38 03 ac 75 26 ae be 0a 47 5d 38 
b8 c2 24 7a b5 1c 48 98 df 70 47 dc 6a df 52 c6 
c4 

# --------------------------------
# RSASSA-PSS Signature Example 2.4
# --------------------------------

# Message to be signed:
a7 18 2c 83 ac 18 be 65 70 a1 06 aa 9d 5c 4e 3d 
bb d4 af ae b0 c6 0c 4a 23 e1 96 9d 79 ff 

# Salt:
80 70 ef 2d e9 45 c0 23 87 68 4b a0 d3 30 96 73 
22 35 d4 40 

# Signature:
00 9c d2 f4 ed be 23 e1 23 46 ae 8c 76 dd 9a d3 
23 0a 62 07 61 41 f1 6c 15 2b a1 85 13 a4 8e f6 
f0 10 e0 e3 7f d3 df 10 a1 ec 62 9a 0c b5 a3 b5 
d2 89 30 07 29 8c 30 93 6a 95 90 3b 6b a8 55 55 
d9 ec 36 73 a0 61 08 fd 62 a2 fd a5 6d 1c e2 e8 
5c 4d b6 b2 4a 81 ca 3b 49 6c 36 d4 fd 06 eb 7c 
91 66 d8 e9 48 77 c4 2b ea 62 2b 3b fe 92 51 fd 
c2 1d 8d 53 71 ba da d7 8a 48 82 14 79 63 35 b4 
0b 

# --------------------------------
# RSASSA-PSS Signature Example 2.5
# --------------------------------

# Message to be signed:
86 a8 3d 4a 72 ee 93 2a 4f 56 30 af 65 79 a3 86 
b7 8f e8 89 99 e0 ab d2 d4 90 34 a4 bf c8 54 dd 
94 f1 09 4e 2e 8c d7 a1 79 d1 95 88 e4 ae fc 1b 
1b d2 5e 95 e3 dd 46 1f 

# Salt:
17 63 9a 4e 88 d7 22 c4 fc a2 4d 07 9a 8b 29 c3 
24 33 b0 c9 

# Signature:
00 ec 43 08 24 93 1e bd 3b aa 43 03 4d ae 98 ba 
64 6b 8c 36 01 3d 16 71 c3 cf 1c f8 26 0c 37 4b 
19 f8 e1 cc 8d 96 50 12 40 5e 7e 9b f7 37 86 12 
df cc 85 fc e1 2c da 11 f9 50 bd 0b a8 87 67 40 
43 6c 1d 25 95 a6 4a 1b 32 ef cf b7 4a 21 c8 73 
b3 cc 33 aa f4 e3 dc 39 53 de 67 f0 67 4c 04 53 
b4 fd 9f 60 44 06 d4 41 b8 16 09 8c b1 06 fe 34 
72 bc 25 1f 81 5f 59 db 2e 43 78 a3 ad dc 18 1e 
cf 

# --------------------------------
# RSASSA-PSS Signature Example 2.6
# --------------------------------

# Message to be signed:
04 9f 91 54 d8 71 ac 4a 7c 7a b4 53 25 ba 75 45 
a1 ed 08 f7 05 25 b2 66 7c f1 

# Salt:
37 81 0d ef 10 55 ed 92 2b 06 3d f7 98 de 5d 0a 
ab f8 86 ee 

# Signature:
00 47 5b 16 48 f8 14 a8 dc 0a bd c3 7b 55 27 f5 
43 b6 66 bb 6e 39 d3 0e 5b 49 d3 b8 76 dc cc 58 
ea c1 4e 32 a2 d5 5c 26 16 01 44 56 ad 2f 24 6f 
c8 e3 d5 60 da 3d df 37 9a 1c 0b d2 00 f1 02 21 
df 07 8c 21 9a 15 1b c8 d4 ec 9d 2f c2 56 44 67 
81 10 14 ef 15 d8 ea 01 c2 eb bf f8 c2 c8 ef ab 
38 09 6e 55 fc be 32 85 c7 aa 55 88 51 25 4f af 
fa 92 c1 c7 2b 78 75 86 63 ef 45 82 84 31 39 d7 
a6 

# =============================================

# ==================================
# Example 3: A 1026-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
02 f2 46 ef 45 1e d3 ee bb 9a 31 02 00 cc 25 85 
9c 04 8e 4b e7 98 30 29 91 11 2e b6 8c e6 db 67 
4e 28 0d a2 1f ed ed 1a e7 48 80 ca 52 2b 18 db 
24 93 85 01 28 27 c5 15 f0 e4 66 a1 ff a6 91 d9 
81 70 57 4e 9d 0e ad b0 87 58 6c a4 89 33 da 3c 
c9 53 d9 5b d0 ed 50 de 10 dd cb 67 36 10 7d 6c 
83 1c 7f 66 3e 83 3c a4 c0 97 e7 00 ce 0f b9 45 
f8 8f b8 5f e8 e5 a7 73 17 25 65 b9 14 a4 71 a4 
43 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
65 14 51 73 3b 56 de 5a c0 a6 89 a4 ae b6 e6 89 
4a 69 01 4e 07 6c 88 dd 7a 66 7e ab 32 32 bb cc 
d2 fc 44 ba 2f a9 c3 1d b4 6f 21 ed d1 fd b2 3c 
5c 12 8a 5d a5 ba b9 1e 7f 95 2b 67 75 9c 7c ff 
70 54 15 ac 9f a0 90 7c 7c a6 17 8f 66 8f b9 48 
d8 69 da 4c c3 b7 35 6f 40 08 df d5 44 9d 32 ee 
02 d9 a4 77 eb 69 fc 29 26 6e 5d 90 70 51 23 75 
a5 0f bb cc 27 e2 38 ad 98 42 5f 6e bb f8 89 91 

# Prime p: 
01 bd 36 e1 8e ce 4b 0f db 2e 9c 9d 54 8b d1 a7 
d6 e2 c2 1c 6f dc 35 07 4a 1d 05 b1 c6 c8 b3 d5 
58 ea 26 39 c9 a9 a4 21 68 01 69 31 72 52 55 8b 
d1 48 ad 21 5a ac 55 0e 2d cf 12 a8 2d 0e bf e8 
53 

# Prime q: 
01 b1 b6 56 ad 86 d8 e1 9d 5d c8 62 92 b3 a1 92 
fd f6 e0 dd 37 87 7b ad 14 82 2f a0 01 90 ca b2 
65 f9 0d 3f 02 05 7b 6f 54 d6 ec b1 44 91 e5 ad 
ea ce bc 48 bf 0e bd 2a 2a d2 6d 40 2e 54 f6 16 
51 

# p's CRT exponent dP: 
1f 27 79 fd 2e 3e 5e 6b ae 05 53 95 18 fb a0 cd 
0e ad 1a a4 51 3a 7c ba 18 f1 cf 10 e3 f6 81 95 
69 3d 27 8a 0f 0e e7 2f 89 f9 bc 76 0d 80 e2 f9 
d0 26 1d 51 65 01 c6 ae 39 f1 4a 47 6c e2 cc f5 

# q's CRT exponent dQ: 
01 1a 0d 36 79 4b 04 a8 54 aa b4 b2 46 2d 43 9a 
50 46 c9 1d 94 0b 2b c6 f7 5b 62 95 6f ef 35 a2 
a6 e6 3c 53 09 81 7f 30 7b bf f9 d5 9e 7e 33 1b 
d3 63 f6 d6 68 49 b1 83 46 ad ea 16 9f 0a e9 ae 
c1 

# CRT coefficient qInv: 
0b 30 f0 ec f5 58 75 2f b3 a6 ce 4b a2 b8 c6 75 
f6 59 eb a6 c3 76 58 5a 1b 39 71 2d 03 8a e3 d2 
b4 6f cb 41 8a e1 5d 09 05 da 64 40 e1 51 3a 30 
b9 b7 d6 66 8f bc 5e 88 e5 ab 7a 17 5e 73 ba 35 

# --------------------------------
# RSASSA-PSS Signature Example 3.1
# --------------------------------

# Message to be signed:
59 4b 37 33 3b bb 2c 84 52 4a 87 c1 a0 1f 75 fc 
ec 0e 32 56 f1 08 e3 8d ca 36 d7 0d 00 57 

# Salt:
f3 1a d6 c8 cf 89 df 78 ed 77 fe ac bc c2 f8 b0 
a8 e4 cf aa 

# Signature:
00 88 b1 35 fb 17 94 b6 b9 6c 4a 3e 67 81 97 f8 
ca c5 2b 64 b2 fe 90 7d 6f 27 de 76 11 24 96 4a 
99 a0 1a 88 27 40 ec fa ed 6c 01 a4 74 64 bb 05 
18 23 13 c0 13 38 a8 cd 09 72 14 cd 68 ca 10 3b 
d5 7d 3b c9 e8 16 21 3e 61 d7 84 f1 82 46 7a bf 
8a 01 cf 25 3e 99 a1 56 ea a8 e3 e1 f9 0e 3c 6e 
4e 3a a2 d8 3e d0 34 5b 89 fa fc 9c 26 07 7c 14 
b6 ac 51 45 4f a2 6e 44 6e 3a 2f 15 3b 2b 16 79 
7f 

# --------------------------------
# RSASSA-PSS Signature Example 3.2
# --------------------------------

# Message to be signed:
8b 76 95 28 88 4a 0d 1f fd 09 0c f1 02 99 3e 79 
6d ad cf bd dd 38 e4 4f f6 32 4c a4 51 

# Salt:
fc f9 f0 e1 f1 99 a3 d1 d0 da 68 1c 5b 86 06 fc 
64 29 39 f7 

# Signature:
02 a5 f0 a8 58 a0 86 4a 4f 65 01 7a 7d 69 45 4f 
3f 97 3a 29 99 83 9b 7b bc 48 bf 78 64 11 69 17 
95 56 f5 95 fa 41 f6 ff 18 e2 86 c2 78 30 79 bc 
09 10 ee 9c c3 4f 49 ba 68 11 24 f9 23 df a8 8f 
42 61 41 a3 68 a5 f5 a9 30 c6 28 c2 c3 c2 00 e1 
8a 76 44 72 1a 0c be c6 dd 3f 62 79 bd e3 e8 f2 
be 5e 2d 4e e5 6f 97 e7 ce af 33 05 4b e7 04 2b 
d9 1a 63 bb 09 f8 97 bd 41 e8 11 97 de e9 9b 11 
af 

# --------------------------------
# RSASSA-PSS Signature Example 3.3
# --------------------------------

# Message to be signed:
1a bd ba 48 9c 5a da 2f 99 5e d1 6f 19 d5 a9 4d 
9e 6e c3 4a 8d 84 f8 45 57 d2 6e 5e f9 b0 2b 22 
88 7e 3f 9a 4b 69 0a d1 14 92 09 c2 0c 61 43 1f 
0c 01 7c 36 c2 65 7b 35 d7 b0 7d 3f 5a d8 70 85 
07 a9 c1 b8 31 df 83 5a 56 f8 31 07 18 14 ea 5d 
3d 8d 8f 6a de 40 cb a3 8b 42 db 7a 2d 3d 7a 29 
c8 f0 a7 9a 78 38 cf 58 a9 75 7f a2 fe 4c 40 df 
9b aa 19 3b fc 6f 92 b1 23 ad 57 b0 7a ce 3e 6a 
c0 68 c9 f1 06 af d9 ee b0 3b 4f 37 c2 5d bf bc 
fb 30 71 f6 f9 77 17 66 d0 72 f3 bb 07 0a f6 60 
55 32 97 3a e2 50 51 

# Salt:
98 6e 7c 43 db b6 71 bd 41 b9 a7 f4 b6 af c8 0e 
80 5f 24 23 

# Signature:
02 44 bc d1 c8 c1 69 55 73 6c 80 3b e4 01 27 2e 
18 cb 99 08 11 b1 4f 72 db 96 41 24 d5 fa 76 06 
49 cb b5 7a fb 87 55 db b6 2b f5 1f 46 6c f2 3a 
0a 16 07 57 6e 98 3d 77 8f ce ff a9 2d f7 54 8a 
ea 8e a4 ec ad 2c 29 dd 9f 95 bc 07 fe 91 ec f8 
be e2 55 bf e8 76 2f d7 69 0a a9 bf a4 fa 08 49 
ef 72 8c 2c 42 c4 53 23 64 52 2d f2 ab 7f 9f 8a 
03 b6 3f 7a 49 91 75 82 86 68 f5 ef 5a 29 e3 80 
2c 

# --------------------------------
# RSASSA-PSS Signature Example 3.4
# --------------------------------

# Message to be signed:
8f b4 31 f5 ee 79 2b 6c 2a c7 db 53 cc 42 86 55 
ae b3 2d 03 f4 e8 89 c5 c2 5d e6 83 c4 61 b5 3a 
cf 89 f9 f8 d3 aa bd f6 b9 f0 c2 a1 de 12 e1 5b 
49 ed b3 91 9a 65 2f e9 49 1c 25 a7 fc e1 f7 22 
c2 54 36 08 b6 9d c3 75 ec 

# Salt:
f8 31 2d 9c 8e ea 13 ec 0a 4c 7b 98 12 0c 87 50 
90 87 c4 78 

# Signature:
01 96 f1 2a 00 5b 98 12 9c 8d f1 3c 4c b1 6f 8a 
a8 87 d3 c4 0d 96 df 3a 88 e7 53 2e f3 9c d9 92 
f2 73 ab c3 70 bc 1b e6 f0 97 cf eb bf 01 18 fd 
9e f4 b9 27 15 5f 3d f2 2b 90 4d 90 70 2d 1f 7b 
a7 a5 2b ed 8b 89 42 f4 12 cd 7b d6 76 c9 d1 8e 
17 03 91 dc d3 45 c0 6a 73 09 64 b3 f3 0b cc e0 
bb 20 ba 10 6f 9a b0 ee b3 9c f8 a6 60 7f 75 c0 
34 7f 0a f7 9f 16 af a0 81 d2 c9 2d 1e e6 f8 36 
b8 

# --------------------------------
# RSASSA-PSS Signature Example 3.5
# --------------------------------

# Message to be signed:
fe f4 16 1d fa af 9c 52 95 05 1d fc 1f f3 81 0c 
8c 9e c2 e8 66 f7 07 54 22 c8 ec 42 16 a9 c4 ff 
49 42 7d 48 3c ae 10 c8 53 4a 41 b2 fd 15 fe e0 
69 60 ec 6f b3 f7 a7 e9 4a 2f 8a 2e 3e 43 dc 4a 
40 57 6c 30 97 ac 95 3b 1d e8 6f 0b 4e d3 6d 64 
4f 23 ae 14 42 55 29 62 24 64 ca 0c bf 0b 17 41 
34 72 38 15 7f ab 59 e4 de 55 24 09 6d 62 ba ec 
63 ac 64 

# Salt:
50 32 7e fe c6 29 2f 98 01 9f c6 7a 2a 66 38 56 
3e 9b 6e 2d 

# Signature:
02 1e ca 3a b4 89 22 64 ec 22 41 1a 75 2d 92 22 
10 76 d4 e0 1c 0e 6f 0d de 9a fd 26 ba 5a cf 6d 
73 9e f9 87 54 5d 16 68 3e 56 74 c9 e7 0f 1d e6 
49 d7 e6 1d 48 d0 ca eb 4f b4 d8 b2 4f ba 84 a6 
e3 10 8f ee 7d 07 05 97 32 66 ac 52 4b 4a d2 80 
f7 ae 17 dc 59 d9 6d 33 51 58 6b 5a 3b db 89 5d 
1e 1f 78 20 ac 61 35 d8 75 34 80 99 83 82 ba 32 
b7 34 95 59 60 8c 38 74 52 90 a8 5e f4 e9 f9 bd 
83 

# --------------------------------
# RSASSA-PSS Signature Example 3.6
# --------------------------------

# Message to be signed:
ef d2 37 bb 09 8a 44 3a ee b2 bf 6c 3f 8c 81 b8 
c0 1b 7f cb 3f eb 

# Salt:
b0 de 3f c2 5b 65 f5 af 96 b1 d5 cc 3b 27 d0 c6 
05 30 87 b3 

# Signature:
01 2f af ec 86 2f 56 e9 e9 2f 60 ab 0c 77 82 4f 
42 99 a0 ca 73 4e d2 6e 06 44 d5 d2 22 c7 f0 bd 
e0 39 64 f8 e7 0a 5c b6 5e d4 4e 44 d5 6a e0 ed 
f1 ff 86 ca 03 2c c5 dd 44 04 db b7 6a b8 54 58 
6c 44 ee d8 33 6d 08 d4 57 ce 6c 03 69 3b 45 c0 
f1 ef ef 93 62 4b 95 b8 ec 16 9c 61 6d 20 e5 53 
8e bc 0b 67 37 a6 f8 2b 4b c0 57 09 24 fc 6b 35 
75 9a 33 48 42 62 79 f8 b3 d7 74 4e 2d 22 24 26 
ce 

# =============================================

# ==================================
# Example 4: A 1027-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
05 4a db 78 86 44 7e fe 6f 57 e0 36 8f 06 cf 52 
b0 a3 37 07 60 d1 61 ce f1 26 b9 1b e7 f8 9c 42 
1b 62 a6 ec 1d a3 c3 11 d7 5e d5 0e 0a b5 ff f3 
fd 33 8a cc 3a a8 a4 e7 7e e2 63 69 ac b8 1b a9 
00 fa 83 f5 30 0c f9 bb 6c 53 ad 1d c8 a1 78 b8 
15 db 42 35 a9 a9 da 0c 06 de 4e 61 5e a1 27 7c 
e5 59 e9 c1 08 de 58 c1 4a 81 aa 77 f5 a6 f8 d1 
33 54 94 49 88 48 c8 b9 59 40 74 0b e7 bf 7c 37 
05 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
fa 04 1f 8c d9 69 7c ee d3 8e c8 ca a2 75 52 3b 
4d d7 2b 09 a3 01 d3 54 1d 72 f5 d3 1c 05 cb ce 
2d 69 83 b3 61 83 af 10 69 0b d4 6c 46 13 1e 35 
78 94 31 a5 56 77 1d d0 04 9b 57 46 1b f0 60 c1 
f6 84 72 e8 a6 7c 25 f3 57 e5 b6 b4 73 8f a5 41 
a7 30 34 6b 4a 07 64 9a 2d fa 80 6a 69 c9 75 b6 
ab a6 46 78 ac c7 f5 91 3e 89 c6 22 f2 d8 ab b1 
e3 e3 25 54 e3 9d f9 4b a6 0c 00 2e 38 7d 90 11 

# Prime p: 
02 92 32 33 6d 28 38 94 5d ba 9d d7 72 3f 4e 62 
4a 05 f7 37 5b 92 7a 87 ab e6 a8 93 a1 65 8f d4 
9f 47 f6 c7 b0 fa 59 6c 65 fa 68 a2 3f 0a b4 32 
96 2d 18 d4 34 3b d6 fd 67 1a 5e a8 d1 48 41 39 
95 

# Prime q: 
02 0e f5 ef e7 c5 39 4a ed 22 72 f7 e8 1a 74 f4 
c0 2d 14 58 94 cb 1b 3c ab 23 a9 a0 71 0a 2a fc 
7e 33 29 ac bb 74 3d 01 f6 80 c4 d0 2a fb 4c 8f 
de 7e 20 93 08 11 bb 2b 99 57 88 b5 e8 72 c2 0b 
b1 

# p's CRT exponent dP: 
02 6e 7e 28 01 0e cf 24 12 d9 52 3a d7 04 64 7f 
b4 fe 9b 66 b1 a6 81 58 1b 0e 15 55 3a 89 b1 54 
28 28 89 8f 27 24 3e ba b4 5f f5 e1 ac b9 d4 df 
1b 05 1f bc 62 82 4d bc 6f 6c 93 26 1a 78 b9 a7 
59 

# q's CRT exponent dQ: 
01 2d dc c8 6e f6 55 99 8c 39 dd ae 11 71 86 69 
e5 e4 6c f1 49 5b 07 e1 3b 10 14 cd 69 b3 af 68 
30 4a d2 a6 b6 43 21 e7 8b f3 bb ca 9b b4 94 e9 
1d 45 17 17 e2 d9 75 64 c6 54 94 65 d0 20 5c f4 
21 

# CRT coefficient qInv: 
01 06 00 c4 c2 18 47 45 9f e5 76 70 3e 2e be ca 
e8 a5 09 4e e6 3f 53 6b f4 ac 68 d3 c1 3e 5e 4f 
12 ac 5c c1 0a b6 a2 d0 5a 19 92 14 d1 82 47 47 
d5 51 90 96 36 b7 74 c2 2c ac 0b 83 75 99 ab cc 
75 

# --------------------------------
# RSASSA-PSS Signature Example 4.1
# --------------------------------

# Message to be signed:
9f b0 3b 82 7c 82 17 d9 

# Salt:
ed 7c 98 c9 5f 30 97 4f be 4f bd dc f0 f2 8d 60 
21 c0 e9 1d 

# Signature:
03 23 d5 b7 bf 20 ba 45 39 28 9a e4 52 ae 42 97 
08 0f ef f4 51 84 23 ff 48 11 a8 17 83 7e 7d 82 
f1 83 6c df ab 54 51 4f f0 88 7b dd ee bf 40 bf 
99 b0 47 ab c3 ec fa 6a 37 a3 ef 00 f4 a0 c4 a8 
8a ae 09 04 b7 45 c8 46 c4 10 7e 87 97 72 3e 8a 
c8 10 d9 e3 d9 5d fa 30 ff 49 66 f4 d7 5d 13 76 
8d 20 85 7f 2b 14 06 f2 64 cf e7 5e 27 d7 65 2f 
4b 5e d3 57 5f 28 a7 02 f8 c4 ed 9c f9 b2 d4 49 
48 

# --------------------------------
# RSASSA-PSS Signature Example 4.2
# --------------------------------

# Message to be signed:
0c a2 ad 77 79 7e ce 86 de 5b f7 68 75 0d db 5e 
d6 a3 11 6a d9 9b bd 17 ed f7 f7 82 f0 db 1c d0 
5b 0f 67 74 68 c5 ea 42 0d c1 16 b1 0e 80 d1 10 
de 2b 04 61 ea 14 a3 8b e6 86 20 39 2e 7e 89 3c 
b4 ea 93 93 fb 88 6c 20 ff 79 06 42 30 5b f3 02 
00 38 92 e5 4d f9 f6 67 50 9d c5 39 20 df 58 3f 
50 a3 dd 61 ab b6 fa b7 5d 60 03 77 e3 83 e6 ac 
a6 71 0e ee a2 71 56 e0 67 52 c9 4c e2 5a e9 9f 
cb f8 59 2d be 2d 7e 27 45 3c b4 4d e0 71 00 eb 
b1 a2 a1 98 11 a4 78 ad be ab 27 0f 94 e8 fe 36 
9d 90 b3 ca 61 2f 9f 

# Salt:
22 d7 1d 54 36 3a 42 17 aa 55 11 3f 05 9b 33 84 
e3 e5 7e 44 

# Signature:
04 9d 01 85 84 5a 26 4d 28 fe b1 e6 9e da ec 09 
06 09 e8 e4 6d 93 ab b3 83 71 ce 51 f4 aa 65 a5 
99 bd aa a8 1d 24 fb a6 6a 08 a1 16 cb 64 4f 3f 
1e 65 3d 95 c8 9d b8 bb d5 da ac 27 09 c8 98 40 
00 17 84 10 a7 c6 aa 86 67 dd c3 8c 74 1f 71 0e 
c8 66 5a a9 05 2b e9 29 d4 e3 b1 67 82 c1 66 21 
14 c5 41 4b b0 35 34 55 c3 92 fc 28 f3 db 59 05 
4b 5f 36 5c 49 e1 d1 56 f8 76 ee 10 cb 4f d7 05 
98 

# --------------------------------
# RSASSA-PSS Signature Example 4.3
# --------------------------------

# Message to be signed:
28 80 62 af c0 8f cd b7 c5 f8 65 0b 29 83 73 00 
46 1d d5 67 6c 17 a2 0a 3c 8f b5 14 89 49 e3 f7 
3d 66 b3 ae 82 c7 24 0e 27 c5 b3 ec 43 28 ee 7d 
6d df 6a 6a 0c 9b 5b 15 bc da 19 6a 9d 0c 76 b1 
19 d5 34 d8 5a bd 12 39 62 d5 83 b7 6c e9 d1 80 
bc e1 ca 

# Salt:
4a f8 70 fb c6 51 60 12 ca 91 6c 70 ba 86 2a c7 
e8 24 36 17 

# Signature:
03 fb c4 10 a2 ce d5 95 00 fb 99 f9 e2 af 27 81 
ad a7 4e 13 14 56 24 60 27 82 e2 99 48 13 ee fc 
a0 51 9e cd 25 3b 85 5f b6 26 a9 0d 77 1e ae 02 
8b 0c 47 a1 99 cb d9 f8 e3 26 97 34 af 41 63 59 
90 90 71 3a 3f a9 10 fa 09 60 65 27 21 43 2b 97 
10 36 a7 18 1a 2b c0 ca b4 3b 0b 59 8b c6 21 74 
61 d7 db 30 5f f7 e9 54 c5 b5 bb 23 1c 39 e7 91 
af 6b cf a7 6b 14 7b 08 13 21 f7 26 41 48 2a 2a 
ad 

# --------------------------------
# RSASSA-PSS Signature Example 4.4
# --------------------------------

# Message to be signed:
6f 4f 9a b9 50 11 99 ce f5 5c 6c f4 08 fe 7b 36 
c5 57 c4 9d 42 0a 47 63 d2 46 3c 8a d4 4b 3c fc 
5b e2 74 2c 0e 7d 9b 0f 66 08 f0 8c 7f 47 b6 93 
ee 

# Salt:
40 d2 e1 80 fa e1 ea c4 39 c1 90 b5 6c 2c 0e 14 
dd f9 a2 26 

# Signature:
04 86 64 4b c6 6b f7 5d 28 33 5a 61 79 b1 08 51 
f4 3f 09 bd ed 9f ac 1a f3 32 52 bb 99 53 ba 42 
98 cd 64 66 b2 75 39 a7 0a da a3 f8 9b 3d b3 c7 
4a b6 35 d1 22 f4 ee 7c e5 57 a6 1e 59 b8 2f fb 
78 66 30 e5 f9 db 53 c7 7d 9a 0c 12 fa b5 95 8d 
4c 2c e7 da a8 07 cd 89 ba 2c c7 fc d0 2f f4 70 
ca 67 b2 29 fc ce 81 4c 85 2c 73 cc 93 be a3 5b 
e6 84 59 ce 47 8e 9d 46 55 d1 21 c8 47 2f 37 1d 
4f 

# --------------------------------
# RSASSA-PSS Signature Example 4.5
# --------------------------------

# Message to be signed:
e1 7d 20 38 5d 50 19 55 82 3c 3f 66 62 54 c1 d3 
dd 36 ad 51 68 b8 f1 8d 28 6f dc f6 7a 7d ad 94 
09 70 85 fa b7 ed 86 fe 21 42 a2 87 71 71 79 97 
ef 1a 7a 08 88 4e fc 39 35 6d 76 07 7a af 82 45 
9a 7f ad 45 84 88 75 f2 81 9b 09 89 37 fe 92 3b 
cc 9d c4 42 d7 2d 75 4d 81 20 25 09 0c 9b c0 3d 
b3 08 0c 13 8d d6 3b 35 5d 0b 4b 85 d6 68 8a c1 
9f 4d e1 50 84 a0 ba 4e 37 3b 93 ef 4a 55 50 96 
69 19 15 dc 23 c0 0e 95 4c de b2 0a 47 cd 55 d1 
6c 3d 86 81 d4 6e d7 f2 ed 5e a4 27 95 be 17 ba 
ed 25 f0 f4 d1 13 b3 63 6a dd d5 85 f1 6a 8b 5a 
ec 0c 8f a9 c5 f0 3c bf 3b 9b 73 

# Salt:
24 97 dc 2b 46 15 df ae 5a 66 3d 49 ff d5 6b f7 
ef c1 13 04 

# Signature:
02 2a 80 04 53 53 90 4c b3 0c bb 54 2d 7d 49 90 
42 1a 6e ec 16 a8 02 9a 84 22 ad fd 22 d6 af f8 
c4 cc 02 94 af 11 0a 0c 06 7e c8 6a 7d 36 41 34 
45 9b b1 ae 8f f8 36 d5 a8 a2 57 98 40 99 6b 32 
0b 19 f1 3a 13 fa d3 78 d9 31 a6 56 25 da e2 73 
9f 0c 53 67 0b 35 d9 d3 cb ac 08 e7 33 e4 ec 2b 
83 af 4b 91 96 d6 3e 7c 4f f1 dd ea e2 a1 22 79 
1a 12 5b fe a8 de b0 de 8c cf 1f 4f fa f6 e6 fb 
0a 

# --------------------------------
# RSASSA-PSS Signature Example 4.6
# --------------------------------

# Message to be signed:
af bc 19 d4 79 24 90 18 fd f4 e0 9f 61 87 26 44 
04 95 de 11 dd ee e3 88 72 d7 75 fc ea 74 a2 38 
96 b5 34 3c 9c 38 d4 6a f0 db a2 24 d0 47 58 0c 
c6 0a 65 e9 39 1c f9 b5 9b 36 a8 60 59 8d 4e 82 
16 72 2f 99 3b 91 cf ae 87 bc 25 5a f8 9a 6a 19 
9b ca 4a 39 1e ad bc 3a 24 90 3c 0b d6 67 36 8f 
6b e7 8e 3f ea bf b4 ff d4 63 12 27 63 74 0f fb 
be fe ab 9a 25 56 4b c5 d1 c2 4c 93 e4 22 f7 50 
73 e2 ad 72 bf 45 b1 0d f0 0b 52 a1 47 12 8e 73 
fe e3 3f a3 f0 57 7d 77 f8 0f bc 2d f1 be d3 13 
29 0c 12 77 7f 50 

# Salt:
a3 34 db 6f ae bf 11 08 1a 04 f8 7c 2d 62 1c de 
c7 93 0b 9b 

# Signature:
00 93 8d cb 6d 58 30 46 06 5f 69 c7 8d a7 a1 f1 
75 70 66 a7 fa 75 12 5a 9d 29 29 f0 b7 9a 60 b6 
27 b0 82 f1 1f 5b 19 6f 28 eb 9d aa 6f 21 c0 5e 
51 40 f6 ae f1 73 7d 20 23 07 5c 05 ec f0 4a 02 
8c 68 6a 2a b3 e7 d5 a0 66 4f 29 5c e1 29 95 e8 
90 90 8b 6a d2 1f 08 39 eb 65 b7 03 93 a7 b5 af 
d9 87 1d e0 ca a0 ce de c5 b8 19 62 67 56 20 9d 
13 ab 1e 7b b9 54 6a 26 ff 37 e9 a5 1a f9 fd 56 
2e 

# =============================================

# ==================================
# Example 5: A 1028-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
0d 10 f6 61 f2 99 40 f5 ed 39 aa 26 09 66 de b4 
78 43 67 9d 2b 6f b2 5b 3d e3 70 f3 ac 7c 19 91 
63 91 fd 25 fb 52 7e bf a6 a4 b4 df 45 a1 75 9d 
99 6c 4b b4 eb d1 88 28 c4 4f c5 2d 01 91 87 17 
40 52 5f 47 a4 b0 cc 8d a3 25 ed 8a a6 76 b0 d0 
f6 26 e0 a7 7f 07 69 21 70 ac ac 80 82 f4 2f aa 
7d c7 cd 12 3e 73 0e 31 a8 79 85 20 4c ab cb e6 
67 0d 43 a2 dd 2b 2d de f5 e0 53 92 fc 21 3b c5 
07 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
03 ce 08 b1 04 ff f3 96 a9 79 bd 3e 4e 46 92 5b 
63 19 dd b6 3a cb cf d8 19 f1 7d 16 b8 07 7b 3a 
87 10 1f f3 4b 77 fe 48 b8 b2 05 a9 6e 91 51 ba 
8e ce a6 4d 0c ce 7b 23 c3 e6 a6 b8 30 58 bc 49 
da e8 16 ae 73 6d b5 a4 70 8e 2a d4 35 23 2b 56 
7f 90 96 ce 59 ff 28 06 1e 79 ab 1c 02 d7 17 e6 
b2 3c ea 6d b8 eb 51 92 fa 7c 1e ab 22 7d ba 74 
62 1c 45 60 18 96 ee f1 37 92 c8 44 0b eb 15 aa 
c1 

# Prime p: 
03 f2 f3 31 f4 14 2d 4f 24 b4 3a a1 02 79 a8 96 
52 d4 e7 53 72 21 a1 a7 b2 a2 5d eb 55 1e 5d e9 
ac 49 74 11 c2 27 a9 4e 45 f9 1c 2d 1c 13 cc 04 
6c f4 ce 14 e3 2d 05 87 34 21 0d 44 a8 7e e1 b7 
3f 

# Prime q: 
03 4f 09 0d 73 b5 58 03 03 0c f0 36 1a 5d 80 81 
bf b7 9f 85 15 23 fe ac 0a 21 24 d0 8d 40 13 ff 
08 48 77 71 a8 70 d0 47 9d c0 68 6c 62 f7 71 8d 
fe cf 02 4b 17 c9 26 76 78 05 91 71 33 9c c0 08 
39 

# p's CRT exponent dP: 
02 aa 66 3a db f5 1a b8 87 a0 18 cb 42 6e 78 bc 
2f e1 82 dc b2 f7 bc b5 04 41 d1 7f df 0f 06 79 
8b 50 71 c6 e2 f5 fe b4 d5 4a d8 18 23 11 c1 ef 
62 d4 c4 9f 18 d1 f5 1f 54 b2 d2 cf fb a4 da 1b 
e5 

# q's CRT exponent dQ: 
02 bb e7 06 07 8b 5c 0b 39 15 12 d4 11 db 1b 19 
9b 5a 56 64 b8 40 42 ea d3 7f e9 94 ae 72 b9 53 
2d fb fb 3e 9e 69 81 a0 fb b8 06 51 31 41 b7 c2 
16 3f e5 6c 39 5e 4b fa ee 57 e3 83 3f 9b 91 8d 
f9 

# CRT coefficient qInv: 
02 42 b6 cd 00 d3 0a 76 7a ee 9a 89 8e ad 45 3c 
8e ae a6 3d 50 0b 7d 1e 00 71 3e da e5 1c e3 6b 
23 b6 64 df 26 e6 3e 26 6e c8 f7 6e 6e 63 ed 1b 
a4 1e b0 33 b1 20 f7 ea 52 12 ae 21 a9 8f bc 16 

# --------------------------------
# RSASSA-PSS Signature Example 5.1
# --------------------------------

# Message to be signed:
30 c7 d5 57 45 8b 43 6d ec fd c1 4d 06 cb 7b 96 
b0 67 18 c4 8d 7d e5 74 82 a8 68 ae 7f 06 58 70 
a6 21 65 06 d1 1b 77 93 23 df df 04 6c f5 77 51 
29 13 4b 4d 56 89 e4 d9 c0 ce 1e 12 d7 d4 b0 6c 
b5 fc 58 20 de cf a4 1b af 59 bf 25 7b 32 f0 25 
b7 67 9b 44 5b 94 99 c9 25 55 14 58 85 99 2f 1b 
76 f8 48 91 ee 4d 3b e0 f5 15 0f d5 90 1e 3a 4c 
8e d4 3f d3 6b 61 d0 22 e6 5a d5 00 8d bf 33 29 
3c 22 bf bf d0 73 21 f0 f1 d5 fa 9f df 00 14 c2 
fc b0 35 8a ad 0e 35 4b 0d 29 

# Salt:
08 1b 23 3b 43 56 77 50 bd 6e 78 f3 96 a8 8b 9f 
6a 44 51 51 

# Signature:
0b a3 73 f7 6e 09 21 b7 0a 8f bf e6 22 f0 bf 77 
b2 8a 3d b9 8e 36 10 51 c3 d7 cb 92 ad 04 52 91 
5a 4d e9 c0 17 22 f6 82 3e eb 6a df 7e 0c a8 29 
0f 5d e3 e5 49 89 0a c2 a3 c5 95 0a b2 17 ba 58 
59 08 94 95 2d e9 6f 8d f1 11 b2 57 52 15 da 6c 
16 15 90 c7 45 be 61 24 76 ee 57 8e d3 84 ab 33 
e3 ec e9 74 81 a2 52 f5 c7 9a 98 b5 53 2a e0 0c 
dd 62 f2 ec c0 cd 1b ae fe 80 d8 0b 96 21 93 ec 
1d 

# --------------------------------
# RSASSA-PSS Signature Example 5.2
# --------------------------------

# Message to be signed:
e7 b3 2e 15 56 ea 1b 27 95 04 6a c6 97 39 d2 2a 
c8 96 6b f1 1c 11 6f 61 4b 16 67 40 e9 6b 90 65 
3e 57 50 94 5f cf 77 21 86 c0 37 90 a0 7f da 32 
3e 1a 61 91 6b 06 ee 21 57 db 3d ff 80 d6 7d 5e 
39 a5 3a e2 68 c8 f0 9e d9 9a 73 20 05 b0 bc 6a 
04 af 4e 08 d5 7a 00 e7 20 1b 30 60 ef aa db 73 
11 3b fc 08 7f d8 37 09 3a a2 52 35 b8 c1 49 f5 
62 15 f0 31 c2 4a d5 bd e7 f2 99 60 df 7d 52 40 
70 f7 44 9c 6f 78 50 84 be 1a 0f 73 30 47 f3 36 
f9 15 47 38 67 45 47 db 02 a9 f4 4d fc 6e 60 30 
10 81 e1 ce 99 84 7f 3b 5b 60 1f f0 6b 4d 57 76 
a9 74 0b 9a a0 d3 40 58 fd 3b 90 6e 4f 78 59 df 
b0 7d 71 73 e5 e6 f6 35 0a da c2 1f 27 b2 30 74 
69 

# Salt:
bd 0c e1 95 49 d0 70 01 20 cb e5 10 77 db bb b0 
0a 8d 8b 09 

# Signature:
08 18 0d e8 25 e4 b8 b0 14 a3 2d a8 ba 76 15 55 
92 12 04 f2 f9 0d 5f 24 b7 12 90 8f f8 4f 3e 22 
0a d1 79 97 c0 dd 6e 70 66 30 ba 3e 84 ad d4 d5 
e7 ab 00 4e 58 07 4b 54 97 09 56 5d 43 ad 9e 97 
b5 a7 a1 a2 9e 85 b9 f9 0f 4a af cd f5 83 21 de 
8c 59 74 ef 9a bf 2d 52 6f 33 c0 f2 f8 2e 95 d1 
58 ea 6b 81 f1 73 6d b8 d1 af 3d 6a c6 a8 3b 32 
d1 8b ae 0f f1 b2 fe 27 de 4c 76 ed 8c 79 80 a3 
4e 

# --------------------------------
# RSASSA-PSS Signature Example 5.3
# --------------------------------

# Message to be signed:
8d 83 96 e3 65 07 fe 1e f6 a1 90 17 54 8e 0c 71 
66 74 c2 fe c2 33 ad b2 f7 75 66 5e c4 1f 2b d0 
ba 39 6b 06 1a 9d aa 7e 86 6f 7c 23 fd 35 31 95 
43 00 a3 42 f9 24 53 5e a1 49 8c 48 f6 c8 79 93 
28 65 fc 02 00 0c 52 87 23 b7 ad 03 35 74 5b 51 
20 9a 0a fe d9 32 af 8f 08 87 c2 19 00 4d 2a bd 
89 4e a9 25 59 ee 31 98 af 3a 73 4f e9 b9 63 8c 
26 3a 72 8a d9 5a 5a e8 ce 3e b1 58 39 f3 aa 78 
52 bb 39 07 06 e7 76 0e 43 a7 12 91 a2 e3 f8 27 
23 7d ed a8 51 87 4c 51 76 65 f5 45 f2 72 38 df 
86 55 7f 37 5d 09 cc d8 bd 15 d8 cc f6 1f 5d 78 
ca 5c 7f 5c de 78 2e 6b f5 d0 05 70 56 d4 ba d9 
8b 3d 2f 95 75 e8 24 ab 7a 33 ff 57 b0 ac 10 0a 
b0 d6 ea d7 aa 0b 50 f6 e4 d3 e5 ec 0b 96 6b 

# Salt:
81 57 79 a9 1b 3a 8b d0 49 bf 2a eb 92 01 42 77 
22 22 c9 ca 

# Signature:
05 e0 fd bd f6 f7 56 ef 73 31 85 cc fa 8c ed 2e 
b6 d0 29 d9 d5 6e 35 56 1b 5d b8 e7 02 57 ee 6f 
d0 19 d2 f0 bb f6 69 fe 9b 98 21 e7 8d f6 d4 1e 
31 60 8d 58 28 0f 31 8e e3 4f 55 99 41 c8 df 13 
28 75 74 ba c0 00 b7 e5 8d c4 f4 14 ba 49 fb 12 
7f 9d 0f 89 36 63 8c 76 e8 53 56 c9 94 f7 97 50 
f7 fa 3c f4 fd 48 2d f7 5e 3f b9 97 8c d0 61 f7 
ab b1 75 72 e6 e6 3e 0b de 12 cb dc f1 8c 68 b9 
79 

# --------------------------------
# RSASSA-PSS Signature Example 5.4
# --------------------------------

# Message to be signed:
32 8c 65 9e 0a 64 37 43 3c ce b7 3c 14 

# Salt:
9a ec 4a 74 80 d5 bb c4 29 20 d7 ca 23 5d b6 74 
98 9c 9a ac 

# Signature:
0b c9 89 85 3b c2 ea 86 87 32 71 ce 18 3a 92 3a 
b6 5e 8a 53 10 0e 6d f5 d8 7a 24 c4 19 4e b7 97 
81 3e e2 a1 87 c0 97 dd 87 2d 59 1d a6 0c 56 86 
05 dd 7e 74 2d 5a f4 e3 3b 11 67 8c cb 63 90 32 
04 a3 d0 80 b0 90 2c 89 ab a8 86 8f 00 9c 0f 1c 
0c b8 58 10 bb dd 29 12 1a bb 84 71 ff 2d 39 e4 
9f d9 2d 56 c6 55 c8 e0 37 ad 18 fa fb dc 92 c9 
58 63 f7 f6 1e a9 ef a2 8f ea 40 13 69 d1 9d ae 
a1 

# --------------------------------
# RSASSA-PSS Signature Example 5.5
# --------------------------------

# Message to be signed:
f3 7b 96 23 79 a4 7d 41 5a 37 6e ec 89 73 15 0b 
cb 34 ed d5 ab 65 40 41 b6 14 30 56 0c 21 44 58 
2b a1 33 c8 67 d8 52 d6 b8 e2 33 21 90 13 02 ec 
b4 5b 09 ec 88 b1 52 71 78 fa 04 32 63 f3 06 7d 
9f fe 97 30 32 a9 9f 4c b0 8a d2 c7 e0 a2 45 6c 
dd 57 a7 df 56 fe 60 53 52 7a 5a eb 67 d7 e5 52 
06 3c 1c a9 7b 1b ef fa 7b 39 e9 97 ca f2 78 78 
ea 0f 62 cb eb c8 c2 1d f4 c8 89 a2 02 85 1e 94 
90 88 49 0c 24 9b 6e 9a cf 1d 80 63 f5 be 23 43 
98 9b f9 5c 4d a0 1a 2b e7 8b 4a b6 b3 78 01 5b 
c3 79 57 f7 69 48 b5 e5 8e 44 0c 28 45 3d 40 d7 
cf d5 7e 7d 69 06 00 47 4a b5 e7 59 73 b1 ea 0c 
5f 1e 45 d1 41 90 af e2 f4 eb 6d 3b df 71 f1 d2 
f8 bb 15 6a 1c 29 5d 04 aa eb 9d 68 9d ce 79 ed 
62 bc 44 3e 

# Salt:
e2 0c 1e 98 78 51 2c 39 97 0f 58 37 5e 15 49 a6 
8b 64 f3 1d 

# Signature:
0a ef a9 43 b6 98 b9 60 9e df 89 8a d2 27 44 ac 
28 dc 23 94 97 ce a3 69 cb bd 84 f6 5c 95 c0 ad 
77 6b 59 47 40 16 4b 59 a7 39 c6 ff 7c 2f 07 c7 
c0 77 a8 6d 95 23 8f e5 1e 1f cf 33 57 4a 4a e0 
68 4b 42 a3 f6 bf 67 7d 91 82 0c a8 98 74 46 7b 
2c 23 ad d7 79 69 c8 07 17 43 0d 0e fc 1d 36 95 
89 2c e8 55 cb 7f 70 11 63 0f 4d f2 6d ef 8d df 
36 fc 23 90 5f 57 fa 62 43 a4 85 c7 70 d5 68 1f 
cd 

# --------------------------------
# RSASSA-PSS Signature Example 5.6
# --------------------------------

# Message to be signed:
c6 10 3c 33 0c 1e f7 18 c1 41 e4 7b 8f a8 59 be 
4d 5b 96 25 9e 7d 14 20 70 ec d4 85 83 9d ba 5a 
83 69 c1 7c 11 14 03 5e 53 2d 19 5c 74 f4 4a 04 
76 a2 d3 e8 a4 da 21 00 16 ca ce d0 e3 67 cb 86 
77 10 a4 b5 aa 2d f2 b8 e5 da f5 fd c6 47 80 7d 
4d 5e bb 6c 56 b9 76 3c cd ae 4d ea 33 08 eb 0a 
c2 a8 95 01 cb 20 9d 26 39 fa 5b f8 7c e7 90 74 
7d 3c b2 d2 95 e8 45 64 f2 f6 37 82 4f 0c 13 02 
81 29 b0 aa 4a 42 2d 16 22 82 

# Salt:
23 29 1e 4a 33 07 e8 bb b7 76 62 3a b3 4e 4a 5f 
4c c8 a8 db 

# Signature:
02 80 2d cc fa 8d fa f5 27 9b f0 b4 a2 9b a1 b1 
57 61 1f ae aa f4 19 b8 91 9d 15 94 19 00 c1 33 
9e 7e 92 e6 fa e5 62 c5 3e 6c c8 e8 41 04 b1 10 
bc e0 3a d1 85 25 e3 c4 9a 0e ad ad 5d 3f 28 f2 
44 a8 ed 89 ed ba fb b6 86 27 7c fa 8a e9 09 71 
4d 6b 28 f4 bf 8e 29 3a a0 4c 41 ef e7 c0 a8 12 
66 d5 c0 61 e2 57 5b e0 32 aa 46 46 74 ff 71 62 
62 19 bd 74 cc 45 f0 e7 ed 4e 3f f9 6e ee 75 8e 
8f 

# =============================================

# ==================================
# Example 6: A 1029-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
16 4c a3 1c ff 60 9f 3a 0e 71 01 b0 39 f2 e4 fe 
6d d3 75 19 ab 98 59 8d 17 9e 17 49 96 59 80 71 
f4 7d 3a 04 55 91 58 d7 be 37 3c f1 aa 53 f0 aa 
6e f0 90 39 e5 67 8c 2a 4c 63 90 05 14 c8 c4 f8 
aa ed 5d e1 2a 5f 10 b0 9c 31 1a f8 c0 ff b5 b7 
a2 97 f2 ef c6 3b 8d 6b 05 10 93 1f 0b 98 e4 8b 
f5 fc 6e c4 e7 b8 db 1f fa eb 08 c3 8e 02 ad b8 
f0 3a 48 22 9c 99 e9 69 43 1f 61 cb 8c 4d c6 98 
d1 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
03 b6 64 ee 3b 75 66 72 3f c6 ea f2 8a bb 43 0a 
39 80 f1 12 6c 81 de 8a d7 09 ea b3 9a c9 dc d0 
b1 55 0b 37 29 d8 70 68 e9 52 00 9d f5 44 53 4c 
1f 50 82 9a 78 f4 59 1e b8 fd 57 14 04 26 a6 bb 
04 05 b6 a6 f5 1a 57 d9 26 7b 7b bc 65 33 91 a6 
99 a2 a9 0d ac 8a e2 26 bc c6 0f a8 cd 93 4c 73 
c7 b0 3b 1f 6b 81 81 58 63 18 38 a8 61 2e 6e 6e 
a9 2b e2 4f 83 24 fa f5 b1 fd 85 87 22 52 67 ba 
6f 

# Prime p: 
04 f0 54 8c 96 26 ab 1e bf 12 44 93 47 41 d9 9a 
06 22 0e fa 2a 58 56 aa 0e 75 73 0b 2e c9 6a dc 
86 be 89 4f a2 80 3b 53 a5 e8 5d 27 6a cb d2 9a 
b8 23 f8 0a 73 91 bb 54 a5 05 16 72 fb 04 ee b5 
43 

# Prime q: 
04 83 e0 ae 47 91 55 87 74 3f f3 45 36 2b 55 5d 
39 62 d9 8b b6 f1 5f 84 8b 4c 92 b1 77 1c a8 ed 
10 7d 8d 3e e6 5e c4 45 17 dd 0f aa 48 1a 38 7e 
90 2f 7a 2e 74 7c 26 9e 7e a4 44 80 bc 53 8b 8e 
5b 

# p's CRT exponent dP: 
03 a8 e8 ae a9 92 0c 1a a3 b2 f0 d8 46 e4 b8 50 
d8 1c a3 06 a5 1c 83 54 4f 94 9f 64 f9 0d cf 3f 
8e 26 61 f0 7e 56 12 20 a1 80 38 8f be 27 3e 70 
e2 e5 dc a8 3a 0e 13 48 dd 64 90 c7 31 d6 ec e1 
ab 

# q's CRT exponent dQ: 
01 35 bd cd b6 0b f2 19 7c 43 6e d3 4b 32 cd 8b 
4f c7 77 78 83 2b a7 67 03 55 1f b2 42 b3 01 69 
95 93 af 77 fd 8f c3 94 a8 52 6a d2 3c c4 1a 03 
80 6b d8 97 fe 4b 0e a6 46 55 8a ad dc c9 9e 8a 
25 

# CRT coefficient qInv: 
03 04 c0 3d 9c 73 65 03 a9 84 ab bd 9b a2 23 01 
40 7c 4a 2a b1 dd 85 76 64 81 b6 0d 45 40 11 52 
e6 92 be 14 f4 12 1d 9a a3 fd 6e 0b 4d 1d 3a 97 
35 38 a3 1d 42 ee 6e 1e 5e f6 20 23 1a 2b ba f3 
5f 

# --------------------------------
# RSASSA-PSS Signature Example 6.1
# --------------------------------

# Message to be signed:
0a 20 b7 74 ad dc 2f a5 12 45 ed 7c b9 da 60 9e 
50 ca c6 63 6a 52 54 3f 97 45 8e ed 73 40 f8 d5 
3f fc 64 91 8f 94 90 78 ee 03 ef 60 d4 2b 5f ec 
24 60 50 bd 55 05 cd 8c b5 97 ba d3 c4 e7 13 b0 
ef 30 64 4e 76 ad ab b0 de 01 a1 56 1e fb 25 51 
58 c7 4f c8 01 e6 e9 19 e5 81 b4 6f 0f 0d dd 08 
e4 f3 4c 78 10 b5 ed 83 18 f9 1d 7c 8c 

# Salt:
5b 4e a2 ef 62 9c c2 2f 3b 53 8e 01 69 04 b4 7b 
1e 40 bf d5 

# Signature:
04 c0 cf ac ec 04 e5 ba db ec e1 59 a5 a1 10 3f 
69 b3 f3 2b a5 93 cb 4c c4 b1 b7 ab 45 59 16 a9 
6a 27 cd 26 78 ea 0f 46 ba 37 f7 fc 9c 86 32 5f 
29 73 3b 38 9f 1d 97 f4 3e 72 01 c0 f3 48 fc 45 
fe 42 89 23 35 36 2e ee 01 8b 5b 16 1f 2f 93 93 
03 12 25 c7 13 01 2a 57 6b c8 8e 23 05 24 89 86 
8d 90 10 cb f0 33 ec c5 68 e8 bc 15 2b dc 59 d5 
60 e4 12 91 91 5d 28 56 52 08 e2 2a ee c9 ef 85 
d1 

# --------------------------------
# RSASSA-PSS Signature Example 6.2
# --------------------------------

# Message to be signed:
2a af f6 63 1f 62 1c e6 15 76 0a 9e bc e9 4b b3 
33 07 7a d8 64 88 c8 61 d4 b7 6d 29 c1 f4 87 46 
c6 11 ae 1e 03 ce d4 44 5d 7c fa 1f e5 f6 2e 1b 
3f 08 45 2b de 3b 6e f8 19 73 ba fb b5 7f 97 bc 
ee f8 73 98 53 95 b8 26 05 89 aa 88 cb 7d b5 0a 
b4 69 26 2e 55 1b dc d9 a5 6f 27 5a 0a c4 fe 48 
47 00 c3 5f 3d bf 2b 46 9e de 86 47 41 b8 6f a5 
91 72 a3 60 ba 95 a0 2e 13 9b e5 0d df b7 cf 0b 
42 fa ea bb fb ba a8 6a 44 97 69 9c 4f 2d fd 5b 
08 40 6a f7 e1 41 44 42 7c 25 3e c0 ef a2 0e af 
9a 8b e8 cd 49 ce 1f 1b c4 e9 3e 61 9c f2 aa 8e 
d4 fb 39 bc 85 90 d0 f7 b9 64 88 f7 31 7a c9 ab 
f7 be e4 e3 a0 e7 15 

# Salt:
83 14 6a 9e 78 27 22 c2 8b 01 4f 98 b4 26 7b da 
2a c9 50 4f 

# Signature:
0a 23 14 25 0c f5 2b 6e 4e 90 8d e5 b3 56 46 bc 
aa 24 36 1d a8 16 0f b0 f9 25 75 90 ab 3a ce 42 
b0 dc 3e 77 ad 2d b7 c2 03 a2 0b d9 52 fb b5 6b 
15 67 04 6e cf aa 93 3d 7b 10 00 c3 de 9f f0 5b 
7d 98 9b a4 6f d4 3b c4 c2 d0 a3 98 6b 7f fa 13 
47 1d 37 eb 5b 47 d6 47 07 bd 29 0c fd 6a 9f 39 
3a d0 8e c1 e3 bd 71 bb 57 92 61 50 35 cd af 2d 
89 29 ae d3 be 09 83 79 37 7e 77 7c e7 9a aa 47 
73 

# --------------------------------
# RSASSA-PSS Signature Example 6.3
# --------------------------------

# Message to be signed:
0f 61 95 d0 4a 6e 6f c7 e2 c9 60 0d bf 84 0c 39 
ea 8d 4d 62 4f d5 35 07 01 6b 0e 26 85 8a 5e 0a 
ec d7 ad a5 43 ae 5c 0a b3 a6 25 99 cb a0 a5 4e 
6b f4 46 e2 62 f9 89 97 8f 9d df 5e 9a 41 

# Salt:
a8 7b 8a ed 07 d7 b8 e2 da f1 4d dc a4 ac 68 c4 
d0 aa bf f8 

# Signature:
08 6d f6 b5 00 09 8c 12 0f 24 ff 84 23 f7 27 d9 
c6 1a 5c 90 07 d3 b6 a3 1c e7 cf 8f 3c be c1 a2 
6b b2 0e 2b d4 a0 46 79 32 99 e0 3e 37 a2 1b 40 
19 4f b0 45 f9 0b 18 bf 20 a4 79 92 cc d7 99 cf 
9c 05 9c 29 9c 05 26 85 49 54 aa de 8a 6a d9 d9 
7e c9 1a 11 45 38 3f 42 46 8b 23 1f 4d 72 f2 37 
06 d9 85 3c 3f a4 3c e8 ac e8 bf e7 48 49 87 a1 
ec 6a 16 c8 da f8 1f 7c 8b f4 27 74 70 7a 9d f4 
56 

# --------------------------------
# RSASSA-PSS Signature Example 6.4
# --------------------------------

# Message to be signed:
33 7d 25 fe 98 10 eb ca 0d e4 d4 65 8d 3c eb 8e 
0f e4 c0 66 ab a3 bc c4 8b 10 5d 3b f7 e0 25 7d 
44 fe ce a6 59 6f 4d 0c 59 a0 84 02 83 36 78 f7 
06 20 f9 13 8d fe b7 de d9 05 e4 a6 d5 f0 5c 47 
3d 55 93 66 52 e2 a5 df 43 c0 cf da 7b ac af 30 
87 f4 52 4b 06 cf 42 15 7d 01 53 97 39 f7 fd de 
c9 d5 81 25 df 31 a3 2e ab 06 c1 9b 71 f1 d5 bf 

# Salt:
a3 79 32 f8 a7 49 4a 94 2d 6f 76 74 38 e7 24 d6 
d0 c0 ef 18 

# Signature:
0b 5b 11 ad 54 98 63 ff a9 c5 1a 14 a1 10 6c 2a 
72 cc 8b 64 6e 5c 72 62 50 97 86 10 5a 98 47 76 
53 4c a9 b5 4c 1c c6 4b f2 d5 a4 4f d7 e8 a6 9d 
b6 99 d5 ea 52 08 7a 47 48 fd 2a bc 1a fe d1 e5 
d6 f7 c8 90 25 53 0b da a2 21 3d 7e 03 0f a5 5d 
f6 f3 4b cf 1c e4 6d 2e df 4e 3a e4 f3 b0 18 91 
a0 68 c9 e3 a4 4b bc 43 13 3e da d6 ec b9 f3 54 
00 c4 25 2a 57 62 d6 57 44 b9 9c b9 f4 c5 59 32 
9f 

# --------------------------------
# RSASSA-PSS Signature Example 6.5
# --------------------------------

# Message to be signed:
84 ec 50 2b 07 2e 82 87 78 9d 8f 92 35 82 9e a3 
b1 87 af d4 d4 c7 85 61 1b da 5f 9e b3 cb 96 71 
7e fa 70 07 22 7f 1c 08 cb cb 97 2e 66 72 35 e0 
fb 7d 43 1a 65 70 32 6d 2e cc e3 5a db 37 3d c7 
53 b3 be 5f 82 9b 89 17 54 93 19 3f ab 16 ba db 
41 37 1b 3a ac 0a e6 70 07 6f 24 be f4 20 c1 35 
ad d7 ce e8 d3 5f bc 94 4d 79 fa fb 9e 30 7a 13 
b0 f5 56 cb 65 4a 06 f9 73 ed 22 67 23 30 19 7e 
f5 a7 48 bf 82 6a 5d b2 38 3a 25 36 4b 68 6b 93 
72 bb 23 39 ae b1 ac 9e 98 89 32 7d 01 6f 16 70 
77 6d b0 62 01 ad bd ca f8 a5 e3 b7 4e 10 8b 73 

# Salt:
7b 79 0c 1d 62 f7 b8 4e 94 df 6a f2 89 17 cf 57 
10 18 11 0e 

# Signature:
02 d7 1f a9 b5 3e 46 54 fe fb 7f 08 38 5c f6 b0 
ae 3a 81 79 42 eb f6 6c 35 ac 67 f0 b0 69 95 2a 
3c e9 c7 e1 f1 b0 2e 48 0a 95 00 83 6d e5 d6 4c 
db 7e cd e0 45 42 f7 a7 99 88 78 7e 24 c2 ba 05 
f5 fd 48 2c 02 3e d5 c3 0e 04 83 9d c4 4b ed 2a 
3a 3a 4f ee 01 11 3c 89 1a 47 d3 2e b8 02 5c 28 
cb 05 0b 5c db 57 6c 70 fe 76 ef 52 34 05 c0 84 
17 fa f3 50 b0 37 a4 3c 37 93 39 fc b1 8d 3a 35 
6b 

# --------------------------------
# RSASSA-PSS Signature Example 6.6
# --------------------------------

# Message to be signed:
99 06 d8 9f 97 a9 fd ed d3 cc d8 24 db 68 73 26 
f3 0f 00 aa 25 a7 fc a2 af cb 3b 0f 86 cd 41 e7 
3f 0e 8f f7 d2 d8 3f 59 e2 8e d3 1a 5a 0d 55 15 
23 37 4d e2 2e 4c 7e 8f f5 68 b3 86 ee 3d c4 11 
63 f1 0b f6 7b b0 06 26 1c 90 82 f9 af 90 bf 1d 
90 49 a6 b9 fa e7 1c 7f 84 fb e6 e5 5f 02 78 9d 
e7 74 f2 30 f1 15 02 6a 4b 4e 96 c5 5b 04 a9 5d 
a3 aa cb b2 ce ce 8f 81 76 4a 1f 1c 99 51 54 11 
08 7c f7 d3 4a ed ed 09 32 c1 83 

# Salt:
fb be 05 90 25 b6 9b 89 fb 14 ae 22 89 e7 aa af 
e6 0c 0f cd 

# Signature:
0a 40 a1 6e 2f e2 b3 8d 1d f9 05 46 16 7c f9 46 
9c 9e 3c 36 81 a3 44 2b 4b 2c 2f 58 1d eb 38 5c 
e9 9f c6 18 8b b0 2a 84 1d 56 e7 6d 30 18 91 e2 
45 60 55 0f cc 2a 26 b5 5f 4c cb 26 d8 37 d3 50 
a1 54 bc ac a8 39 2d 98 fa 67 95 9e 97 27 b7 8c 
ad 03 26 9f 56 96 8f c5 6b 68 bd 67 99 26 d8 3c 
c9 cb 21 55 50 64 5c cd a3 1c 76 0f f3 58 88 94 
3d 2d 8a 1d 35 1e 81 e5 d0 7b 86 18 2e 75 10 81 
ef 

# =============================================

# ==================================
# Example 7: A 1030-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
37 c9 da 4a 66 c8 c4 08 b8 da 27 d0 c9 d7 9f 8c 
cb 1e af c1 d2 fe 48 74 6d 94 0b 7c 4e f5 de e1 
8a d1 26 47 ce fa a0 c4 b3 18 8b 22 1c 51 53 86 
75 9b 93 f0 20 24 b2 5a b9 24 2f 83 57 d8 f3 fd 
49 64 0e e5 e6 43 ea f6 c6 4d ee fa 70 89 72 7c 
8f f0 39 93 33 39 15 c6 ef 21 bf 59 75 b6 e5 0d 
11 8b 51 00 8e c3 3e 9f 01 a0 a5 45 a1 0a 83 6a 
43 dd bc a9 d8 b5 c5 d3 54 80 22 d7 06 4e a2 9a 
b3 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
3b ed 99 90 52 d9 57 bc 06 d6 51 ee f6 e3 a9 80 
94 b1 62 1b d3 8b 54 49 bd 6c 4a ea 3d e7 e0 84 
67 9a 44 84 de d2 5b e0 f0 82 6c f3 37 78 25 41 
4b 14 d4 d6 1d b1 4d e6 26 fb b8 0e 5f 4f ae c9 
56 f9 a0 a2 d2 4f 99 57 63 80 f0 84 eb 62 e4 6a 
57 d5 54 27 8b 53 56 26 19 3c e0 20 60 57 5e b6 
6c 57 98 d3 6f 6c 5d 40 fb 00 d8 09 b4 2a 73 10 
2c 1c 74 ee 95 bd 71 42 0f ff ef 63 18 b5 2c 29 

# Prime p: 
07 ee fb 42 4b 0e 3a 40 e4 20 8e e5 af b2 80 b2 
23 17 30 81 14 dd e0 b4 b6 4f 73 01 84 ec 68 da 
6c e2 86 7a 9f 48 ed 77 26 d5 e2 61 4e d0 4a 54 
10 73 6c 8c 71 4e e7 02 47 42 98 c6 29 2a f0 75 
35 

# Prime q: 
07 08 30 db f9 47 ea c0 22 8d e2 63 14 b5 9b 66 
99 4c c6 0e 83 60 e7 5d 38 76 29 8f 8f 8a 7d 14 
1d a0 64 e5 ca 02 6a 97 3e 28 f2 54 73 8c ee 66 
9c 72 1b 03 4c b5 f8 e2 44 da dd 7c d1 e1 59 d5 
47 

# p's CRT exponent dP: 
05 24 d2 0c 3d 95 cf f7 5a f2 31 34 83 22 7d 87 
02 71 7a a5 76 de 15 5f 96 05 15 50 1a db 1d 70 
e1 c0 4d e9 1b 75 b1 61 db f0 39 83 56 12 7e de 
da 7b bc 19 a3 2d c1 62 1c c9 f5 3c 26 5d 0c e3 
31 

# q's CRT exponent dQ: 
05 f9 84 a1 f2 3c 93 8d 6a 0e 89 72 4b cf 3d d9 
3f 99 46 92 60 37 fe 7c 6b 13 a2 9e 52 84 85 5f 
89 08 95 91 d4 40 97 56 27 bf 5c 9e 3a 8b 5c a7 
9c 77 2a d2 73 e4 0d 32 1a f4 a6 c9 7d fd ed 78 
d3 

# CRT coefficient qInv: 
dd d9 18 ad ad a2 9d ca b9 81 ff 9a cb a4 25 70 
23 c0 9a 38 01 cc ce 09 8c e2 68 f8 55 d0 df 57 
0c d6 e7 b9 b1 4b d9 a5 a9 25 4c bc 31 5b e6 f8 
ba 1e 25 46 dd d5 69 c5 ea 19 ee d8 35 3b de 5e 

# --------------------------------
# RSASSA-PSS Signature Example 7.1
# --------------------------------

# Message to be signed:
9e ad 0e 01 94 56 40 67 4e b4 1c ad 43 5e 23 74 
ea ef a8 ad 71 97 d9 79 13 c4 49 57 d8 d8 3f 40 
d7 6e e6 0e 39 bf 9c 0f 9e af 30 21 42 1a 07 4d 
1a de 96 2c 6e 9d 3d c3 bb 17 4f e4 df e6 52 b0 
91 15 49 5b 8f d2 79 41 74 02 0a 06 02 b5 ca 51 
84 8c fc 96 ce 5e b5 7f c0 a2 ad c1 dd a3 6a 7c 
c4 52 64 1a 14 91 1b 37 e4 5b fa 11 da a5 c7 ec 
db 74 f6 d0 10 0d 1d 3e 39 e7 52 80 0e 20 33 97 
de 02 33 07 7b 9a 88 85 55 37 fa e9 27 f9 24 38 
0d 78 0f 98 e1 8d cf f3 9c 5e a7 41 b1 7d 6f dd 
18 85 bc 9d 58 14 82 d7 71 ce b5 62 d7 8a 8b f8 
8f 0c 75 b1 13 63 e5 e3 6c d4 79 ce b0 54 5f 9d 
a8 42 03 e0 e6 e5 08 37 5c c9 e8 44 b8 8b 7a c7 
a0 a2 01 ea 0f 1b ee 9a 2c 57 79 20 ca 02 c0 1b 
9d 83 20 e9 74 a5 6f 4e fb 57 63 b9 62 55 ab bf 
80 37 bf 18 02 cf 01 8f 56 37 94 93 e5 69 a9 

# Salt:
b7 86 7a 59 95 8c b5 43 28 f8 77 5e 65 46 ec 06 
d2 7e aa 50 

# Signature:
18 7f 39 07 23 c8 90 25 91 f0 15 4b ae 6d 4e cb 
ff e0 67 f0 e8 b7 95 47 6e a4 f4 d5 1c cc 81 05 
20 bb 3c a9 bc a7 d0 b1 f2 ea 8a 17 d8 73 fa 27 
57 0a cd 64 2e 38 08 56 1c b9 e9 75 cc fd 80 b2 
3d c5 77 1c db 33 06 a5 f2 31 59 da cb d3 aa 2d 
b9 3d 46 d7 66 e0 9e d1 5d 90 0a d8 97 a8 d2 74 
dc 26 b4 7e 99 4a 27 e9 7e 22 68 a7 66 53 3a e4 
b5 e4 2a 2f ca f7 55 c1 c4 79 4b 29 4c 60 55 58 
23 

# --------------------------------
# RSASSA-PSS Signature Example 7.2
# --------------------------------

# Message to be signed:
8d 80 d2 d0 8d bd 19 c1 54 df 3f 14 67 3a 14 bd 
03 73 52 31 f2 4e 86 bf 15 3d 0e 69 e7 4c bf f7 
b1 83 6e 66 4d e8 3f 68 01 24 37 0f c0 f9 6c 9b 
65 c0 7a 36 6b 64 4c 4a b3 

# Salt:
0c 09 58 22 66 df 08 63 10 82 1b a7 e1 8d f6 4d 
fe e6 de 09 

# Signature:
10 fd 89 76 8a 60 a6 77 88 ab b5 85 6a 78 7c 85 
61 f3 ed cf 9a 83 e8 98 f7 dc 87 ab 8c ce 79 42 
9b 43 e5 69 06 94 1a 88 61 94 f1 37 e5 91 fe 7c 
33 95 55 36 1f bb e1 f2 4f eb 2d 4b cd b8 06 01 
f3 09 6b c9 13 2d ee a6 0a e1 30 82 f4 4f 9a d4 
1c d6 28 93 6a 4d 51 17 6e 42 fc 59 cb 76 db 81 
5c e5 ab 4d b9 9a 10 4a af ea 68 f5 d3 30 32 9e 
bf 25 8d 4e de 16 06 4b d1 d0 03 93 d5 e1 57 0e 
b8 

# --------------------------------
# RSASSA-PSS Signature Example 7.3
# --------------------------------

# Message to be signed:
80 84 05 cd fc 1a 58 b9 bb 03 97 c7 20 72 2a 81 
ff fb 76 27 8f 33 59 17 ef 9c 47 38 14 b3 e0 16 
ba 29 73 cd 27 65 f8 f3 f8 2d 6c c3 8a a7 f8 55 
18 27 fe 8d 1e 38 84 b7 e6 1c 94 68 3b 8f 82 f1 
84 3b da e2 25 7e ee c9 81 2a d4 c2 cf 28 3c 34 
e0 b0 ae 0f e3 cb 99 0c f8 8f 2e f9 

# Salt:
28 03 9d cf e1 06 d3 b8 29 66 11 25 8c 4a 56 65 
1c 9e 92 dd 

# Signature:
2b 31 fd e9 98 59 b9 77 aa 09 58 6d 8e 27 46 62 
b2 5a 2a 64 06 40 b4 57 f5 94 05 1c b1 e7 f7 a9 
11 86 54 55 24 29 26 cf 88 fe 80 df a3 a7 5b a9 
68 98 44 a1 1e 63 4a 82 b0 75 af bd 69 c1 2a 0d 
f9 d2 5f 84 ad 49 45 df 3d c8 fe 90 c3 ce fd f2 
6e 95 f0 53 43 04 b5 bd ba 20 d3 e5 64 0a 2e bf 
b8 98 aa c3 5a e4 0f 26 fc e5 56 3c 2f 9f 24 f3 
04 2a f7 6f 3c 70 72 d6 87 bb fb 95 9a 88 46 0a 
f1 

# --------------------------------
# RSASSA-PSS Signature Example 7.4
# --------------------------------

# Message to be signed:
f3 37 b9 ba d9 37 de 22 a1 a0 52 df f1 11 34 a8 
ce 26 97 62 02 98 19 39 b9 1e 07 15 ae 5e 60 96 
49 da 1a df ce f3 f4 cc a5 9b 23 83 60 e7 d1 e4 
96 c7 bf 4b 20 4b 5a cf f9 bb d6 16 6a 1d 87 a3 
6e f2 24 73 73 75 10 39 f8 a8 00 b8 39 98 07 b3 
a8 5f 44 89 34 97 c0 d0 5f b7 01 7b 82 22 81 52 
de 6f 25 e6 11 6d cc 75 03 c7 86 c8 75 c2 8f 3a 
a6 07 e9 4a b0 f1 98 63 ab 1b 50 73 77 0b 0c d5 
f5 33 ac de 30 c6 fb 95 3c f3 da 68 02 64 e3 0f 
c1 1b ff 9a 19 bf fa b4 77 9b 62 23 c3 fb 3f e0 
f7 1a ba de 4e b7 c0 9c 41 e2 4c 22 d2 3f a1 48 
e6 a1 73 fe b6 39 84 d1 bc 6e e3 a0 2d 91 5b 75 
2c ea f9 2a 30 15 ec eb 38 ca 58 6c 68 01 b3 7c 
34 ce fb 2c ff 25 ea 23 c0 86 62 dc ab 26 a7 a9 
3a 28 5d 05 d3 04 4c 

# Salt:
a7 78 21 eb bb ef 24 62 8e 4e 12 e1 d0 ea 96 de 
39 8f 7b 0f 

# Signature:
32 c7 ca 38 ff 26 94 9a 15 00 0c 4b a0 4b 2b 13 
b3 5a 38 10 e5 68 18 4d 7e ca ba a1 66 b7 ff ab 
dd f2 b6 cf 4b a0 71 24 92 37 90 f2 e5 b1 a5 be 
04 0a ea 36 fe 13 2e c1 30 e1 f1 05 67 98 2d 17 
ac 3e 89 b8 d2 6c 30 94 03 4e 76 2d 2e 03 12 64 
f0 11 70 be ec b3 d1 43 9e 05 84 6f 25 45 83 67 
a7 d9 c0 20 60 44 46 72 67 1e 64 e8 77 86 45 59 
ca 19 b2 07 4d 58 8a 28 1b 58 04 d2 37 72 fb be 
19 

# --------------------------------
# RSASSA-PSS Signature Example 7.5
# --------------------------------

# Message to be signed:
45 01 3c eb af d9 60 b2 55 47 6a 8e 25 98 b9 aa 
32 ef be 6d c1 f3 4f 4a 49 8d 8c f5 a2 b4 54 8d 
08 c5 5d 5f 95 f7 bc c9 61 91 63 05 6f 2d 58 b5 
2f a0 32 

# Salt:
9d 5a d8 eb 45 21 34 b6 5d c3 a9 8b 6a 73 b5 f7 
41 60 9c d6 

# Signature:
07 eb 65 1d 75 f1 b5 2b c2 63 b2 e1 98 33 6e 99 
fb eb c4 f3 32 04 9a 92 2a 10 81 56 07 ee 2d 98 
9d b3 a4 49 5b 7d cc d3 8f 58 a2 11 fb 7e 19 31 
71 a3 d8 91 13 24 37 eb ca 44 f3 18 b2 80 50 9e 
52 b5 fa 98 fc ce 82 05 d9 69 7c 8e e4 b7 ff 59 
d4 c5 9c 79 03 8a 19 70 bd 2a 0d 45 1e cd c5 ef 
11 d9 97 9c 9d 35 f8 c7 0a 61 63 71 76 07 89 0d 
58 6a 7c 6d c0 1c 79 f8 6a 8f 28 e8 52 35 f8 c2 
f1 

# --------------------------------
# RSASSA-PSS Signature Example 7.6
# --------------------------------

# Message to be signed:
23 58 09 70 86 c8 99 32 3e 75 d9 c9 0d 0c 09 f1 
2d 9d 54 ed fb df 70 a9 c2 eb 5a 04 d8 f3 6b 9b 
2b df 2a ab e0 a5 bd a1 96 89 37 f9 d6 eb d3 b6 
b2 57 ef b3 13 6d 41 31 f9 ac b5 9b 85 e2 60 2c 
2a 3f cd c8 35 49 4a 1f 4e 5e c1 8b 22 6c 80 23 
2b 36 a7 5a 45 fd f0 9a 7e a9 e9 8e fb de 14 50 
d1 19 4b f1 2e 15 a4 c5 f9 eb 5c 0b ce 52 69 e0 
c3 b2 8c fa b6 55 d8 1a 61 a2 0b 4b e2 f5 44 59 
bb 25 a0 db 94 c5 22 18 be 10 9a 74 26 de 83 01 
44 24 78 9a aa 90 e5 05 6e 63 2a 69 81 15 e2 82 
c1 a5 64 10 f2 6c 20 72 f1 93 48 1a 9d cd 88 05 
72 00 5e 64 f4 08 2e cf 

# Salt:
3f 2e fc 59 58 80 a7 d4 7f cf 3c ba 04 98 3e a5 
4c 4b 73 fb 

# Signature:
18 da 3c dc fe 79 bf b7 7f d9 c3 2f 37 7a d3 99 
14 6f 0a 8e 81 06 20 23 32 71 a6 e3 ed 32 48 90 
3f 5c dc 92 dc 79 b5 5d 3e 11 61 5a a0 56 a7 95 
85 37 92 a3 99 8c 34 9c a5 c4 57 e8 ca 7d 29 d7 
96 aa 24 f8 34 91 70 9b ef cf b1 51 0e a5 13 c9 
28 29 a3 f0 0b 10 4f 65 56 34 f3 20 75 2e 13 0e 
c0 cc f6 75 4f f8 93 db 30 29 32 bb 02 5e b6 0e 
87 82 25 98 fc 61 9e 0e 98 17 37 a9 a4 c4 15 2d 
33 

# =============================================

# ==================================
# Example 8: A 1031-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
49 53 70 a1 fb 18 54 3c 16 d3 63 1e 31 63 25 5d 
f6 2b e6 ee e8 90 d5 f2 55 09 e4 f7 78 a8 ea 6f 
bb bc df 85 df f6 4e 0d 97 20 03 ab 36 81 fb ba 
6d d4 1f d5 41 82 9b 2e 58 2d e9 f2 a4 a4 e0 a2 
d0 90 0b ef 47 53 db 3c ee 0e e0 6c 7d fa e8 b1 
d5 3b 59 53 21 8f 9c ce ea 69 5b 08 66 8e de aa 
dc ed 94 63 b1 d7 90 d5 eb f2 7e 91 15 b4 6c ad 
4d 9a 2b 8e fa b0 56 1b 08 10 34 47 39 ad a0 73 
3f 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
6c 66 ff e9 89 80 c3 8f cd ea b5 15 98 98 83 61 
65 f4 b4 b8 17 c4 f6 a8 d4 86 ee 4e a9 13 0f e9 
b9 09 2b d1 36 d1 84 f9 5f 50 4a 60 7e ac 56 58 
46 d2 fd d6 59 7a 89 67 c7 39 6e f9 5a 6e ee bb 
45 78 a6 43 96 6d ca 4d 8e e3 de 84 2d e6 32 79 
c6 18 15 9c 1a b5 4a 89 43 7b 6a 61 20 e4 93 0a 
fb 52 a4 ba 6c ed 8a 49 47 ac 64 b3 0a 34 97 cb 
e7 01 c2 d6 26 6d 51 72 19 ad 0e c6 d3 47 db e9 

# Prime p: 
08 da d7 f1 13 63 fa a6 23 d5 d6 d5 e8 a3 19 32 
8d 82 19 0d 71 27 d2 84 6c 43 9b 0a b7 26 19 b0 
a4 3a 95 32 0e 4e c3 4f c3 a9 ce a8 76 42 23 05 
bd 76 c5 ba 7b e9 e2 f4 10 c8 06 06 45 a1 d2 9e 
db 

# Prime q: 
08 47 e7 32 37 6f c7 90 0f 89 8e a8 2e b2 b0 fc 
41 85 65 fd ae 62 f7 d9 ec 4c e2 21 7b 97 99 0d 
d2 72 db 15 7f 99 f6 3c 0d cb b9 fb ac db d4 c4 
da db 6d f6 77 56 35 8c a4 17 48 25 b4 8f 49 70 
6d 

# p's CRT exponent dP: 
05 c2 a8 3c 12 4b 36 21 a2 aa 57 ea 2c 3e fe 03 
5e ff 45 60 f3 3d de bb 7a da b8 1f ce 69 a0 c8 
c2 ed c1 65 20 dd a8 3d 59 a2 3b e8 67 96 3a c6 
5f 2c c7 10 bb cf b9 6e e1 03 de b7 71 d1 05 fd 
85 

# q's CRT exponent dQ: 
04 ca e8 aa 0d 9f aa 16 5c 87 b6 82 ec 14 0b 8e 
d3 b5 0b 24 59 4b 7a 3b 2c 22 0b 36 69 bb 81 9f 
98 4f 55 31 0a 1a e7 82 36 51 d4 a0 2e 99 44 79 
72 59 51 39 36 34 34 e5 e3 0a 7e 7d 24 15 51 e1 
b9 

# CRT coefficient qInv: 
07 d3 e4 7b f6 86 60 0b 11 ac 28 3c e8 8d bb 3f 
60 51 e8 ef d0 46 80 e4 4c 17 1e f5 31 b8 0b 2b 
7c 39 fc 76 63 20 e2 cf 15 d8 d9 98 20 e9 6f f3 
0d c6 96 91 83 9c 4b 40 d7 b0 6e 45 30 7d c9 1f 
3f 

# --------------------------------
# RSASSA-PSS Signature Example 8.1
# --------------------------------

# Message to be signed:
81 33 2f 4b e6 29 48 41 5e a1 d8 99 79 2e ea cf 
6c 6e 1d b1 da 8b e1 3b 5c ea 41 db 2f ed 46 70 
92 e1 ff 39 89 14 c7 14 25 97 75 f5 95 f8 54 7f 
73 56 92 a5 75 e6 92 3a f7 8f 22 c6 99 7d db 90 
fb 6f 72 d7 bb 0d d5 74 4a 31 de cd 3d c3 68 58 
49 83 6e d3 4a ec 59 63 04 ad 11 84 3c 4f 88 48 
9f 20 97 35 f5 fb 7f da f7 ce c8 ad dc 58 18 16 
8f 88 0a cb f4 90 d5 10 05 b7 a8 e8 4e 43 e5 42 
87 97 75 71 dd 99 ee a4 b1 61 eb 2d f1 f5 10 8f 
12 a4 14 2a 83 32 2e db 05 a7 54 87 a3 43 5c 9a 
78 ce 53 ed 93 bc 55 08 57 d7 a9 fb 

# Salt:
1d 65 49 1d 79 c8 64 b3 73 00 9b e6 f6 f2 46 7b 
ac 4c 78 fa 

# Signature:
02 62 ac 25 4b fa 77 f3 c1 ac a2 2c 51 79 f8 f0 
40 42 2b 3c 5b af d4 0a 8f 21 cf 0f a5 a6 67 cc 
d5 99 3d 42 db af b4 09 c5 20 e2 5f ce 2b 1e e1 
e7 16 57 7f 1e fa 17 f3 da 28 05 2f 40 f0 41 9b 
23 10 6d 78 45 aa f0 11 25 b6 98 e7 a4 df e9 2d 
39 67 bb 00 c4 d0 d3 5b a3 55 2a b9 a8 b3 ee f0 
7c 7f ec db c5 42 4a c4 db 1e 20 cb 37 d0 b2 74 
47 69 94 0e a9 07 e1 7f bb ca 67 3b 20 52 23 80 
c5 

# --------------------------------
# RSASSA-PSS Signature Example 8.2
# --------------------------------

# Message to be signed:
e2 f9 6e af 0e 05 e7 ba 32 6e cc a0 ba 7f d2 f7 
c0 23 56 f3 ce de 9d 0f aa bf 4f cc 8e 60 a9 73 
e5 59 5f d9 ea 08 

# Salt:
43 5c 09 8a a9 90 9e b2 37 7f 12 48 b0 91 b6 89 
87 ff 18 38 

# Signature:
27 07 b9 ad 51 15 c5 8c 94 e9 32 e8 ec 0a 28 0f 
56 33 9e 44 a1 b5 8d 4d dc ff 2f 31 2e 5f 34 dc 
fe 39 e8 9c 6a 94 dc ee 86 db bd ae 5b 79 ba 4e 
08 19 a9 e7 bf d9 d9 82 e7 ee 6c 86 ee 68 39 6e 
8b 3a 14 c9 c8 f3 4b 17 8e b7 41 f9 d3 f1 21 10 
9b f5 c8 17 2f ad a2 e7 68 f9 ea 14 33 03 2c 00 
4a 8a a0 7e b9 90 00 0a 48 dc 94 c8 ba c8 aa be 
2b 09 b1 aa 46 c0 a2 aa 0e 12 f6 3f bb a7 75 ba 
7e 

# --------------------------------
# RSASSA-PSS Signature Example 8.3
# --------------------------------

# Message to be signed:
e3 5c 6e d9 8f 64 a6 d5 a6 48 fc ab 8a db 16 33 
1d b3 2e 5d 15 c7 4a 40 ed f9 4c 3d c4 a4 de 79 
2d 19 08 89 f2 0f 1e 24 ed 12 05 4a 6b 28 79 8f 
cb 42 d1 c5 48 76 9b 73 4c 96 37 31 42 09 2a ed 
27 76 03 f4 73 8d f4 dc 14 46 58 6d 0e c6 4d a4 
fb 60 53 6d b2 ae 17 fc 7e 3c 04 bb fb bb d9 07 
bf 11 7c 08 63 6f a1 6f 95 f5 1a 62 16 93 4d 3e 
34 f8 50 30 f1 7b bb c5 ba 69 14 40 58 af f0 81 
e0 b1 9c f0 3c 17 19 5c 5e 88 8b a5 8f 6f e0 a0 
2e 5c 3b da 97 19 a7 

# Salt:
c6 eb be 76 df 0c 4a ea 32 c4 74 17 5b 2f 13 68 
62 d0 45 29 

# Signature:
2a d2 05 09 d7 8c f2 6d 1b 6c 40 61 46 08 6e 4b 
0c 91 a9 1c 2b d1 64 c8 7b 96 6b 8f aa 42 aa 0c 
a4 46 02 23 23 ba 4b 1a 1b 89 70 6d 7f 4c 3b e5 
7d 7b 69 70 2d 16 8a b5 95 5e e2 90 35 6b 8c 4a 
29 ed 46 7d 54 7e c2 3c ba df 28 6c cb 58 63 c6 
67 9d a4 67 fc 93 24 a1 51 c7 ec 55 aa c6 db 40 
84 f8 27 26 82 5c fe 1a a4 21 bc 64 04 9f b4 2f 
23 14 8f 9c 25 b2 dc 30 04 37 c3 8d 42 8a a7 5f 
96 

# --------------------------------
# RSASSA-PSS Signature Example 8.4
# --------------------------------

# Message to be signed:
db c5 f7 50 a7 a1 4b e2 b9 3e 83 8d 18 d1 4a 86 
95 e5 2e 8a dd 9c 0a c7 33 b8 f5 6d 27 47 e5 29 
a0 cc a5 32 dd 49 b9 02 ae fe d5 14 44 7f 9e 81 
d1 61 95 c2 85 38 68 cb 9b 30 f7 d0 d4 95 c6 9d 
01 b5 c5 d5 0b 27 04 5d b3 86 6c 23 24 a4 4a 11 
0b 17 17 74 6d e4 57 d1 c8 c4 5c 3c d2 a9 29 70 
c3 d5 96 32 05 5d 4c 98 a4 1d 6e 99 e2 a3 dd d5 
f7 f9 97 9a b3 cd 18 f3 75 05 d2 51 41 de 2a 1b 
ff 17 b3 a7 dc e9 41 9e cc 38 5c f1 1d 72 84 0f 
19 95 3f d0 50 92 51 f6 ca fd e2 89 3d 0e 75 c7 
81 ba 7a 50 12 ca 40 1a 4f a9 9e 04 b3 c3 24 9f 
92 6d 5a fe 82 cc 87 da b2 2c 3c 1b 10 5d e4 8e 
34 ac e9 c9 12 4e 59 59 7a c7 eb f8 

# Salt:
02 1f dc c6 eb b5 e1 9b 1c b1 6e 9c 67 f2 76 81 
65 7f e2 0a 

# Signature:
1e 24 e6 e5 86 28 e5 17 50 44 a9 eb 6d 83 7d 48 
af 12 60 b0 52 0e 87 32 7d e7 89 7e e4 d5 b9 f0 
df 0b e3 e0 9e d4 de a8 c1 45 4f f3 42 3b b0 8e 
17 93 24 5a 9d f8 bf 6a b3 96 8c 8e dd c3 b5 32 
85 71 c7 7f 09 1c c5 78 57 69 12 df eb d1 64 b9 
de 54 54 fe 0b e1 c1 f6 38 5b 32 83 60 ce 67 ec 
7a 05 f6 e3 0e b4 5c 17 c4 8a c7 00 41 d2 ca b6 
7f 0a 2a e7 aa fd cc 8d 24 5e a3 44 2a 63 00 cc 
c7 

# --------------------------------
# RSASSA-PSS Signature Example 8.5
# --------------------------------

# Message to be signed:
04 dc 25 1b e7 2e 88 e5 72 34 85 b6 38 3a 63 7e 
2f ef e0 76 60 c5 19 a5 60 b8 bc 18 bd ed b8 6e 
ae 23 64 ea 53 ba 9d ca 6e b3 d2 e7 d6 b8 06 af 
42 b3 e8 7f 29 1b 4a 88 81 d5 bf 57 2c c9 a8 5e 
19 c8 6a cb 28 f0 98 f9 da 03 83 c5 66 d3 c0 f5 
8c fd 8f 39 5d cf 60 2e 5c d4 0e 8c 71 83 f7 14 
99 6e 22 97 ef 

# Salt:
c5 58 d7 16 7c bb 45 08 ad a0 42 97 1e 71 b1 37 
7e ea 42 69 

# Signature:
33 34 1b a3 57 6a 13 0a 50 e2 a5 cf 86 79 22 43 
88 d5 69 3f 5a cc c2 35 ac 95 ad d6 8e 5e b1 ee 
c3 16 66 d0 ca 7a 1c da 6f 70 a1 aa 76 2c 05 75 
2a 51 95 0c db 8a f3 c5 37 9f 18 cf e6 b5 bc 55 
a4 64 82 26 a1 5e 91 2e f1 9a d7 7a de ea 91 1d 
67 cf ef d6 9b a4 3f a4 11 91 35 ff 64 21 17 ba 
98 5a 7e 01 00 32 5e 95 19 f1 ca 6a 92 16 bd a0 
55 b5 78 50 15 29 11 25 e9 0d cd 07 a2 ca 96 73 
ee 

# --------------------------------
# RSASSA-PSS Signature Example 8.6
# --------------------------------

# Message to be signed:
0e a3 7d f9 a6 fe a4 a8 b6 10 37 3c 24 cf 39 0c 
20 fa 6e 21 35 c4 00 c8 a3 4f 5c 18 3a 7e 8e a4 
c9 ae 09 0e d3 17 59 f4 2d c7 77 19 cc a4 00 ec 
dc c5 17 ac fc 7a c6 90 26 75 b2 ef 30 c5 09 66 
5f 33 21 48 2f c6 9a 9f b5 70 d1 5e 01 c8 45 d0 
d8 e5 0d 2a 24 cb f1 cf 0e 71 49 75 a5 db 7b 18 
d9 e9 e9 cb 91 b5 cb 16 86 90 60 ed 18 b7 b5 62 
45 50 3f 0c af 90 35 2b 8d e8 1c b5 a1 d9 c6 33 
60 92 f0 cd 

# Salt:
76 fd 4e 64 fd c9 8e b9 27 a0 40 3e 35 a0 84 e7 
6b a9 f9 2a 

# Signature:
1e d1 d8 48 fb 1e db 44 12 9b d9 b3 54 79 5a f9 
7a 06 9a 7a 00 d0 15 10 48 59 3e 0c 72 c3 51 7f 
f9 ff 2a 41 d0 cb 5a 0a c8 60 d7 36 a1 99 70 4f 
7c b6 a5 39 86 a8 8b bd 8a bc c0 07 6a 2c e8 47 
88 00 31 52 5d 44 9d a2 ac 78 35 63 74 c5 36 e3 
43 fa a7 cb a4 2a 5a aa 65 06 08 77 91 c0 6a 8e 
98 93 35 ae d1 9b fa b2 d5 e6 7e 27 fb 0c 28 75 
af 89 6c 21 b6 e8 e7 30 9d 04 e4 f6 72 7e 69 46 
3e 

# =============================================

# ==================================
# Example 9: A 1536-bit RSA Key Pair
# ==================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
e6 bd 69 2a c9 66 45 79 04 03 fd d0 f5 be b8 b9 
bf 92 ed 10 00 7f c3 65 04 64 19 dd 06 c0 5c 5b 
5b 2f 48 ec f9 89 e4 ce 26 91 09 97 9c bb 40 b4 
a0 ad 24 d2 24 83 d1 ee 31 5a d4 cc b1 53 42 68 
35 26 91 c5 24 f6 dd 8e 6c 29 d2 24 cf 24 69 73 
ae c8 6c 5b f6 b1 40 1a 85 0d 1b 9a d1 bb 8c bc 
ec 47 b0 6f 0f 8c 7f 45 d3 fc 8f 31 92 99 c5 43 
3d db c2 b3 05 3b 47 de d2 ec d4 a4 ca ef d6 14 
83 3d c8 bb 62 2f 31 7e d0 76 b8 05 7f e8 de 3f 
84 48 0a d5 e8 3e 4a 61 90 4a 4f 24 8f b3 97 02 
73 57 e1 d3 0e 46 31 39 81 5c 6f d4 fd 5a c5 b8 
17 2a 45 23 0e cb 63 18 a0 4f 14 55 d8 4e 5a 8b 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
6a 7f d8 4f b8 5f ad 07 3b 34 40 6d b7 4f 8d 61 
a6 ab c1 21 96 a9 61 dd 79 56 5e 9d a6 e5 18 7b 
ce 2d 98 02 50 f7 35 95 75 35 92 70 d9 15 90 bb 
0e 42 7c 71 46 0b 55 d5 14 10 b1 91 bc f3 09 fe 
a1 31 a9 2c 8e 70 27 38 fa 71 9f 1e 00 41 f5 2e 
40 e9 1f 22 9f 4d 96 a1 e6 f1 72 e1 55 96 b4 51 
0a 6d ae c2 61 05 f2 be bc 53 31 6b 87 bd f2 13 
11 66 60 70 e8 df ee 69 d5 2c 71 a9 76 ca ae 79 
c7 2b 68 d2 85 80 dc 68 6d 9f 51 29 d2 25 f8 2b 
3d 61 55 13 a8 82 b3 db 91 41 6b 48 ce 08 88 82 
13 e3 7e eb 9a f8 00 d8 1c ab 32 8c e4 20 68 99 
03 c0 0c 7b 5f d3 1b 75 50 3a 6d 41 96 84 d6 29 

# Prime p: 
f8 eb 97 e9 8d f1 26 64 ee fd b7 61 59 6a 69 dd 
cd 0e 76 da ec e6 ed 4b f5 a1 b5 0a c0 86 f7 92 
8a 4d 2f 87 26 a7 7e 51 5b 74 da 41 98 8f 22 0b 
1c c8 7a a1 fc 81 0c e9 9a 82 f2 d1 ce 82 1e dc 
ed 79 4c 69 41 f4 2c 7a 1a 0b 8c 4d 28 c7 5e c6 
0b 65 22 79 f6 15 4a 76 2a ed 16 5d 47 de e3 67 

# Prime q: 
ed 4d 71 d0 a6 e2 4b 93 c2 e5 f6 b4 bb e0 5f 5f 
b0 af a0 42 d2 04 fe 33 78 d3 65 c2 f2 88 b6 a8 
da d7 ef e4 5d 15 3e ef 40 ca cc 7b 81 ff 93 40 
02 d1 08 99 4b 94 a5 e4 72 8c d9 c9 63 37 5a e4 
99 65 bd a5 5c bf 0e fe d8 d6 55 3b 40 27 f2 d8 
62 08 a6 e6 b4 89 c1 76 12 80 92 d6 29 e4 9d 3d 

# p's CRT exponent dP: 
2b b6 8b dd fb 0c 4f 56 c8 55 8b ff af 89 2d 80 
43 03 78 41 e7 fa 81 cf a6 1a 38 c5 e3 9b 90 1c 
8e e7 11 22 a5 da 22 27 bd 6c de eb 48 14 52 c1 
2a d3 d6 1d 5e 4f 77 6a 0a b5 56 59 1b ef e3 e5 
9e 5a 7f dd b8 34 5e 1f 2f 35 b9 f4 ce e5 7c 32 
41 4c 08 6a ec 99 3e 93 53 e4 80 d9 ee c6 28 9f 

# q's CRT exponent dQ: 
4f f8 97 70 9f ad 07 97 46 49 45 78 e7 0f d8 54 
61 30 ee ab 56 27 c4 9b 08 0f 05 ee 4a d9 f3 e4 
b7 cb a9 d6 a5 df f1 13 a4 1c 34 09 33 68 33 f1 
90 81 6d 8a 6b c4 2e 9b ec 56 b7 56 7d 0f 3c 9c 
69 6d b6 19 b2 45 d9 01 dd 85 6d b7 c8 09 2e 77 
e9 a1 cc cd 56 ee 4d ba 42 c5 fd b6 1a ec 26 69 

# CRT coefficient qInv: 
77 b9 d1 13 7b 50 40 4a 98 27 29 31 6e fa fc 7d 
fe 66 d3 4e 5a 18 26 00 d5 f3 0a 0a 85 12 05 1c 
56 0d 08 1d 4d 0a 18 35 ec 3d 25 a6 0f 4e 4d 6a 
a9 48 b2 bf 3d bb 5b 12 4c bb c3 48 92 55 a3 a9 
48 37 2f 69 78 49 67 45 f9 43 e1 db 4f 18 38 2c 
ea a5 05 df c6 57 57 bb 3f 85 7a 58 dc e5 21 56 

# --------------------------------
# RSASSA-PSS Signature Example 9.1
# --------------------------------

# Message to be signed:
a8 8e 26 58 55 e9 d7 ca 36 c6 87 95 f0 b3 1b 59 
1c d6 58 7c 71 d0 60 a0 b3 f7 f3 ea ef 43 79 59 
22 02 8b c2 b6 ad 46 7c fc 2d 7f 65 9c 53 85 aa 
70 ba 36 72 cd de 4c fe 49 70 cc 79 04 60 1b 27 
88 72 bf 51 32 1c 4a 97 2f 3c 95 57 0f 34 45 d4 
f5 79 80 e0 f2 0d f5 48 46 e6 a5 2c 66 8f 12 88 
c0 3f 95 00 6e a3 2f 56 2d 40 d5 2a f9 fe b3 2f 
0f a0 6d b6 5b 58 8a 23 7b 34 e5 92 d5 5c f9 79 
f9 03 a6 42 ef 64 d2 ed 54 2a a8 c7 7d c1 dd 76 
2f 45 a5 93 03 ed 75 e5 41 ca 27 1e 2b 60 ca 70 
9e 44 fa 06 61 13 1e 8d 5d 41 63 fd 8d 39 85 66 
ce 26 de 87 30 e7 2f 9c ca 73 76 41 c2 44 15 94 
20 63 70 28 df 0a 18 07 9d 62 08 ea 8b 47 11 a2 
c7 50 f5 

# Salt:
c0 a4 25 31 3d f8 d7 56 4b d2 43 4d 31 15 23 d5 
25 7e ed 80 

# Signature:
58 61 07 22 6c 3c e0 13 a7 c8 f0 4d 1a 6a 29 59 
bb 4b 8e 20 5b a4 3a 27 b5 0f 12 41 11 bc 35 ef 
58 9b 03 9f 59 32 18 7c b6 96 d7 d9 a3 2c 0c 38 
30 0a 5c dd a4 83 4b 62 d2 eb 24 0a f3 3f 79 d1 
3d fb f0 95 bf 59 9e 0d 96 86 94 8c 19 64 74 7b 
67 e8 9c 9a ba 5c d8 50 16 23 6f 56 6c c5 80 2c 
b1 3e ad 51 bc 7c a6 be f3 b9 4d cb db b1 d5 70 
46 97 71 df 0e 00 b1 a8 a0 67 77 47 2d 23 16 27 
9e da e8 64 74 66 8d 4e 1e ff f9 5f 1d e6 1c 60 
20 da 32 ae 92 bb f1 65 20 fe f3 cf 4d 88 f6 11 
21 f2 4b bd 9f e9 1b 59 ca f1 23 5b 2a 93 ff 81 
fc 40 3a dd f4 eb de a8 49 34 a9 cd af 8e 1a 9e 

# --------------------------------
# RSASSA-PSS Signature Example 9.2
# --------------------------------

# Message to be signed:
c8 c9 c6 af 04 ac da 41 4d 22 7e f2 3e 08 20 c3 
73 2c 50 0d c8 72 75 e9 5b 0d 09 54 13 99 3c 26 
58 bc 1d 98 85 81 ba 87 9c 2d 20 1f 14 cb 88 ce 
d1 53 a0 19 69 a7 bf 0a 7b e7 9c 84 c1 48 6b c1 
2b 3f a6 c5 98 71 b6 82 7c 8c e2 53 ca 5f ef a8 
a8 c6 90 bf 32 6e 8e 37 cd b9 6d 90 a8 2e ba b6 
9f 86 35 0e 18 22 e8 bd 53 6a 2e 

# Salt:
b3 07 c4 3b 48 50 a8 da c2 f1 5f 32 e3 78 39 ef 
8c 5c 0e 91 

# Signature:
80 b6 d6 43 25 52 09 f0 a4 56 76 38 97 ac 9e d2 
59 d4 59 b4 9c 28 87 e5 88 2e cb 44 34 cf d6 6d 
d7 e1 69 93 75 38 1e 51 cd 7f 55 4f 2c 27 17 04 
b3 99 d4 2b 4b e2 54 0a 0e ca 61 95 1f 55 26 7f 
7c 28 78 c1 22 84 2d ad b2 8b 01 bd 5f 8c 02 5f 
7e 22 84 18 a6 73 c0 3d 6b c0 c7 36 d0 a2 95 46 
bd 67 f7 86 d9 d6 92 cc ea 77 8d 71 d9 8c 20 63 
b7 a7 10 92 18 7a 4d 35 af 10 81 11 d8 3e 83 ea 
e4 6c 46 aa 34 27 7e 06 04 45 89 90 37 88 f1 d5 
e7 ce e2 5f b4 85 e9 29 49 11 88 14 d6 f2 c3 ee 
36 14 89 01 6f 32 7f b5 bc 51 7e b5 04 70 bf fa 
1a fa 5f 4c e9 aa 0c e5 b8 ee 19 bf 55 01 b9 58 

# --------------------------------
# RSASSA-PSS Signature Example 9.3
# --------------------------------

# Message to be signed:
0a fa d4 2c cd 4f c6 06 54 a5 50 02 d2 28 f5 2a 
4a 5f e0 3b 8b bb 08 ca 82 da ca 55 8b 44 db e1 
26 6e 50 c0 e7 45 a3 6d 9d 29 04 e3 40 8a bc d1 
fd 56 99 94 06 3f 4a 75 cc 72 f2 fe e2 a0 cd 89 
3a 43 af 1c 5b 8b 48 7d f0 a7 16 10 02 4e 4f 6d 
df 9f 28 ad 08 13 c1 aa b9 1b cb 3c 90 64 d5 ff 
74 2d ef fe a6 57 09 41 39 36 9e 5e a6 f4 a9 63 
19 a5 cc 82 24 14 5b 54 50 62 75 8f ef d1 fe 34 
09 ae 16 92 59 c6 cd fd 6b 5f 29 58 e3 14 fa ec 
be 69 d2 ca ce 58 ee 55 17 9a b9 b3 e6 d1 ec c1 
4a 55 7c 5f eb e9 88 59 52 64 fc 5d a1 c5 71 46 
2e ca 79 8a 18 a1 a4 94 0c da b4 a3 e9 20 09 cc 
d4 2e 1e 94 7b 13 14 e3 22 38 a2 de ce 7d 23 a8 
9b 5b 30 c7 51 fd 0a 4a 43 0d 2c 54 85 94 

# Salt:
9a 2b 00 7e 80 97 8b bb 19 2c 35 4e b7 da 9a ed 
fc 74 db f5 

# Signature:
48 44 08 f3 89 8c d5 f5 34 83 f8 08 19 ef bf 27 
08 c3 4d 27 a8 b2 a6 fa e8 b3 22 f9 24 02 37 f9 
81 81 7a ca 18 46 f1 08 4d aa 6d 7c 07 95 f6 e5 
bf 1a f5 9c 38 e1 85 84 37 ce 1f 7e c4 19 b9 8c 
87 36 ad f6 dd 9a 00 b1 80 6d 2b d3 ad 0a 73 77 
5e 05 f5 2d fe f3 a5 9a b4 b0 81 43 f0 df 05 cd 
1a d9 d0 4b ec ec a6 da a4 a2 12 98 03 e2 00 cb 
c7 77 87 ca f4 c1 d0 66 3a 6c 59 87 b6 05 95 20 
19 78 2c af 2e c1 42 6d 68 fb 94 ed 1d 4b e8 16 
a7 ed 08 1b 77 e6 ab 33 0b 3f fc 07 38 20 fe cd 
e3 72 7f cb e2 95 ee 61 a0 50 a3 43 65 86 37 c3 
fd 65 9c fb 63 73 6d e3 2d 9f 90 d3 c2 f6 3e ca 

# --------------------------------
# RSASSA-PSS Signature Example 9.4
# --------------------------------

# Message to be signed:
1d fd 43 b4 6c 93 db 82 62 9b da e2 bd 0a 12 b8 
82 ea 04 c3 b4 65 f5 cf 93 02 3f 01 05 96 26 db 
be 99 f2 6b b1 be 94 9d dd d1 6d c7 f3 de bb 19 
a1 94 62 7f 0b 22 44 34 df 7d 87 00 e9 e9 8b 06 
e3 60 c1 2f db e3 d1 9f 51 c9 68 4e b9 08 9e cb 
b0 a2 f0 45 03 99 d3 f5 9e ac 72 94 08 5d 04 4f 
53 93 c6 ce 73 74 23 d8 b8 6c 41 53 70 d3 89 e3 
0b 9f 0a 3c 02 d2 5d 00 82 e8 ad 6f 3f 1e f2 4a 
45 c3 cf 82 b3 83 36 70 63 a4 d4 61 3e 42 64 f0 
1b 2d ac 2e 5a a4 20 43 f8 fb 5f 69 fa 87 1d 14 
fb 27 3e 76 7a 53 1c 40 f0 2f 34 3b c2 fb 45 a0 
c7 e0 f6 be 25 61 92 3a 77 21 1d 66 a6 e2 db b4 
3c 36 63 50 be ae 22 da 3a c2 c1 f5 07 70 96 fc 
b5 c4 bf 25 5f 75 74 35 1a e0 b1 e1 f0 36 32 81 
7c 08 56 d4 a8 ba 97 af bd c8 b8 58 55 40 2b c5 
69 26 fc ec 20 9f 9e a8 

# Salt:
70 f3 82 bd df 4d 5d 2d d8 8b 3b c7 b7 30 8b e6 
32 b8 40 45 

# Signature:
84 eb eb 48 1b e5 98 45 b4 64 68 ba fb 47 1c 01 
12 e0 2b 23 5d 84 b5 d9 11 cb d1 92 6e e5 07 4a 
e0 42 44 95 cb 20 e8 23 08 b8 eb b6 5f 41 9a 03 
fb 40 e7 2b 78 98 1d 88 aa d1 43 05 36 85 17 2c 
97 b2 9c 8b 7b f0 ae 73 b5 b2 26 3c 40 3d a0 ed 
2f 80 ff 74 50 af 78 28 eb 8b 86 f0 02 8b d2 a8 
b1 76 a4 d2 28 cc ce a1 83 94 f2 38 b0 9f f7 58 
cc 00 bc 04 30 11 52 35 57 42 f2 82 b5 4e 66 3a 
91 9e 70 9d 8d a2 4a de 55 00 a7 b9 aa 50 22 6e 
0c a5 29 23 e6 c2 d8 60 ec 50 ff 48 0f a5 74 77 
e8 2b 05 65 f4 37 9f 79 c7 72 d5 c2 da 80 af 9f 
bf 32 5e ce 6f c2 0b 00 96 16 14 be e8 9a 18 3e 

# --------------------------------
# RSASSA-PSS Signature Example 9.5
# --------------------------------

# Message to be signed:
1b dc 6e 7c 98 fb 8c f5 4e 9b 09 7b 66 a8 31 e9 
cf e5 2d 9d 48 88 44 8e e4 b0 97 80 93 ba 1d 7d 
73 ae 78 b3 a6 2b a4 ad 95 cd 28 9c cb 9e 00 52 
26 bb 3d 17 8b cc aa 82 1f b0 44 a4 e2 1e e9 76 
96 c1 4d 06 78 c9 4c 2d ae 93 b0 ad 73 92 22 18 
55 3d aa 7e 44 eb e5 77 25 a7 a4 5c c7 2b 9b 21 
38 a6 b1 7c 8d b4 11 ce 82 79 ee 12 41 af f0 a8 
be c6 f7 7f 87 ed b0 c6 9c b2 72 36 e3 43 5a 80 
0b 19 2e 4f 11 e5 19 e3 fe 30 fc 30 ea cc ca 4f 
bb 41 76 90 29 bf 70 8e 81 7a 9e 68 38 05 be 67 
fa 10 09 84 68 3b 74 83 8e 3b cf fa 79 36 6e ed 
1d 48 1c 76 72 91 18 83 8f 31 ba 8a 04 8a 93 c1 
be 44 24 59 8e 8d f6 32 8b 7a 77 88 0a 3f 9c 7e 
2e 8d fc a8 eb 5a 26 fb 86 bd c5 56 d4 2b be 01 
d9 fa 6e d8 06 46 49 1c 93 41 

# Salt:
d6 89 25 7a 86 ef fa 68 21 2c 5e 0c 61 9e ca 29 
5f b9 1b 67 

# Signature:
82 10 2d f8 cb 91 e7 17 99 19 a0 4d 26 d3 35 d6 
4f bc 2f 87 2c 44 83 39 43 24 1d e8 45 48 10 27 
4c df 3d b5 f4 2d 42 3d b1 52 af 71 35 f7 01 42 
0e 39 b4 94 a6 7c bf d1 9f 91 19 da 23 3a 23 da 
5c 64 39 b5 ba 0d 2b c3 73 ee e3 50 70 01 37 8d 
4a 40 73 85 6b 7f e2 ab a0 b5 ee 93 b2 7f 4a fe 
c7 d4 d1 20 92 1c 83 f6 06 76 5b 02 c1 9e 4d 6a 
1a 3b 95 fa 4c 42 29 51 be 4f 52 13 10 77 ef 17 
17 97 29 cd df bd b5 69 50 db ac ee fe 78 cb 16 
64 0a 09 9e a5 6d 24 38 9e ef 10 f8 fe cb 31 ba 
3e a3 b2 27 c0 a8 66 98 bb 89 e3 e9 36 39 05 bf 
22 77 7b 2a 3a a5 21 b6 5b 4c ef 76 d8 3b de 4c 

 ------------------------------
# RSASSA-PSS Signature Example 9.6
 ------------------------------

# Message to be signed:
88 c7 a9 f1 36 04 01 d9 0e 53 b1 01 b6 1c 53 25 
c3 c7 5d b1 b4 11 fb eb 8e 83 0b 75 e9 6b 56 67 
0a d2 45 40 4e 16 79 35 44 ee 35 4b c6 13 a9 0c 
c9 84 87 15 a7 3d b5 89 3e 7f 6d 27 98 15 c0 c1 
de 83 ef 8e 29 56 e3 a5 6e d2 6a 88 8d 7a 9c dc 
d0 42 f4 b1 6b 7f a5 1e f1 a0 57 36 62 d1 6a 30 
2d 0e c5 b2 85 d2 e0 3a d9 65 29 c8 7b 3d 37 4d 
b3 72 d9 5b 24 43 d0 61 b6 b1 a3 50 ba 87 80 7e 
d0 83 af d1 eb 05 c3 f5 2f 4e ba 5e d2 22 77 14 
fd b5 0b 9d 9d 9d d6 81 4f 62 f6 27 2f cd 5c db 
ce 7a 9e f7 97 

# Salt:
c2 5f 13 bf 67 d0 81 67 1a 04 81 a1 f1 82 0d 61 
3b ba 22 76 

# Signature:
a7 fd b0 d2 59 16 5c a2 c8 8d 00 bb f1 02 8a 86 
7d 33 76 99 d0 61 19 3b 17 a9 64 8e 14 cc bb aa 
de ac aa cd ec 81 5e 75 71 29 4e bb 8a 11 7a f2 
05 fa 07 8b 47 b0 71 2c 19 9e 3a d0 51 35 c5 04 
c2 4b 81 70 51 15 74 08 02 48 79 92 ff d5 11 d4 
af c6 b8 54 49 1e b3 f0 dd 52 31 39 54 2f f1 5c 
31 01 ee 85 54 35 17 c6 a3 c7 94 17 c6 7e 2d d9 
aa 74 1e 9a 29 b0 6d cb 59 3c 23 36 b3 67 0a e3 
af ba c7 c3 e7 6e 21 54 73 e8 66 e3 38 ca 24 4d 
e0 0b 62 62 4d 6b 94 26 82 2c ea e9 f8 cc 46 08 
95 f4 12 50 07 3f d4 5c 5a 1e 7b 42 5c 20 4a 42 
3a 69 91 59 f6 90 3e 71 0b 37 a7 bb 2b c8 04 9f 

# =============================================

# ===================================
# Example 10: A 2048-bit RSA Key Pair
# ===================================

# ------------------------------
# Components of the RSA Key Pair
# ------------------------------

# RSA modulus n: 
a5 dd 86 7a c4 cb 02 f9 0b 94 57 d4 8c 14 a7 70 
ef 99 1c 56 c3 9c 0e c6 5f d1 1a fa 89 37 ce a5 
7b 9b e7 ac 73 b4 5c 00 17 61 5b 82 d6 22 e3 18 
75 3b 60 27 c0 fd 15 7b e1 2f 80 90 fe e2 a7 ad 
cd 0e ef 75 9f 88 ba 49 97 c7 a4 2d 58 c9 aa 12 
cb 99 ae 00 1f e5 21 c1 3b b5 43 14 45 a8 d5 ae 
4f 5e 4c 7e 94 8a c2 27 d3 60 40 71 f2 0e 57 7e 
90 5f be b1 5d fa f0 6d 1d e5 ae 62 53 d6 3a 6a 
21 20 b3 1a 5d a5 da bc 95 50 60 0e 20 f2 7d 37 
39 e2 62 79 25 fe a3 cc 50 9f 21 df f0 4e 6e ea 
45 49 c5 40 d6 80 9f f9 30 7e ed e9 1f ff 58 73 
3d 83 85 a2 37 d6 d3 70 5a 33 e3 91 90 09 92 07 
0d f7 ad f1 35 7c f7 e3 70 0c e3 66 7d e8 3f 17 
b8 df 17 78 db 38 1d ce 09 cb 4a d0 58 a5 11 00 
1a 73 81 98 ee 27 cf 55 a1 3b 75 45 39 90 65 82 
ec 8b 17 4b d5 8d 5d 1f 3d 76 7c 61 37 21 ae 05 

# RSA public exponent e: 
01 00 01 

# RSA private exponent d: 
2d 2f f5 67 b3 fe 74 e0 61 91 b7 fd ed 6d e1 12 
29 0c 67 06 92 43 0d 59 69 18 40 47 da 23 4c 96 
93 de ed 16 73 ed 42 95 39 c9 69 d3 72 c0 4d 6b 
47 e0 f5 b8 ce e0 84 3e 5c 22 83 5d bd 3b 05 a0 
99 79 84 ae 60 58 b1 1b c4 90 7c bf 67 ed 84 fa 
9a e2 52 df b0 d0 cd 49 e6 18 e3 5d fd fe 59 bc 
a3 dd d6 6c 33 ce bb c7 7a d4 41 aa 69 5e 13 e3 
24 b5 18 f0 1c 60 f5 a8 5c 99 4a d1 79 f2 a6 b5 
fb e9 34 02 b1 17 67 be 01 bf 07 34 44 d6 ba 1d 
d2 bc a5 bd 07 4d 4a 5f ae 35 31 ad 13 03 d8 4b 
30 d8 97 31 8c bb ba 04 e0 3c 2e 66 de 6d 91 f8 
2f 96 ea 1d 4b b5 4a 5a ae 10 2d 59 46 57 f5 c9 
78 95 53 51 2b 29 6d ea 29 d8 02 31 96 35 7e 3e 
3a 6e 95 8f 39 e3 c2 34 40 38 ea 60 4b 31 ed c6 
f0 f7 ff 6e 71 81 a5 7c 92 82 6a 26 8f 86 76 8e 
96 f8 78 56 2f c7 1d 85 d6 9e 44 86 12 f7 04 8f 

# Prime p: 
cf d5 02 83 fe ee b9 7f 6f 08 d7 3c bc 7b 38 36 
f8 2b bc d4 99 47 9f 5e 6f 76 fd fc b8 b3 8c 4f 
71 dc 9e 88 bd 6a 6f 76 37 1a fd 65 d2 af 18 62 
b3 2a fb 34 a9 5f 71 b8 b1 32 04 3f fe be 3a 95 
2b af 75 92 44 81 48 c0 3f 9c 69 b1 d6 8e 4c e5 
cf 32 c8 6b af 46 fe d3 01 ca 1a b4 03 06 9b 32 
f4 56 b9 1f 71 89 8a b0 81 cd 8c 42 52 ef 52 71 
91 5c 97 94 b8 f2 95 85 1d a7 51 0f 99 cb 73 eb 

# Prime q: 
cc 4e 90 d2 a1 b3 a0 65 d3 b2 d1 f5 a8 fc e3 1b 
54 44 75 66 4e ab 56 1d 29 71 b9 9f b7 be f8 44 
e8 ec 1f 36 0b 8c 2a c8 35 96 92 97 1e a6 a3 8f 
72 3f cc 21 1f 5d bc b1 77 a0 fd ac 51 64 a1 d4 
ff 7f bb 4e 82 99 86 35 3c b9 83 65 9a 14 8c dd 
42 0c 7d 31 ba 38 22 ea 90 a3 2b e4 6c 03 0e 8c 
17 e1 fa 0a d3 78 59 e0 6b 0a a6 fa 3b 21 6d 9c 
be 6c 0e 22 33 97 69 c0 a6 15 91 3e 5d a7 19 cf 

# p's CRT exponent dP: 
1c 2d 1f c3 2f 6b c4 00 4f d8 5d fd e0 fb bf 9a 
4c 38 f9 c7 c4 e4 1d ea 1a a8 82 34 a2 01 cd 92 
f3 b7 da 52 65 83 a9 8a d8 5b b3 60 fb 98 3b 71 
1e 23 44 9d 56 1d 17 78 d7 a5 15 48 6b cb f4 7b 
46 c9 e9 e1 a3 a1 f7 70 00 ef be b0 9a 8a fe 47 
e5 b8 57 cd a9 9c b1 6d 7f ff 9b 71 2e 3b d6 0c 
a9 6d 9c 79 73 d6 16 d4 69 34 a9 c0 50 28 1c 00 
43 99 ce ff 1d b7 dd a7 87 66 a8 a9 b9 cb 08 73 

# q's CRT exponent dQ: 
cb 3b 3c 04 ca a5 8c 60 be 7d 9b 2d eb b3 e3 96 
43 f4 f5 73 97 be 08 23 6a 1e 9e af aa 70 65 36 
e7 1c 3a cf e0 1c c6 51 f2 3c 9e 05 85 8f ee 13 
bb 6a 8a fc 47 df 4e dc 9a 4b a3 0b ce cb 73 d0 
15 78 52 32 7e e7 89 01 5c 2e 8d ee 7b 9f 05 a0 
f3 1a c9 4e b6 17 31 64 74 0c 5c 95 14 7c d5 f3 
b5 ae 2c b4 a8 37 87 f0 1d 8a b3 1f 27 c2 d0 ee 
a2 dd 8a 11 ab 90 6a ba 20 7c 43 c6 ee 12 53 31 

# CRT coefficient qInv: 
12 f6 b2 cf 13 74 a7 36 fa d0 56 16 05 0f 96 ab 
4b 61 d1 17 7c 7f 9d 52 5a 29 f3 d1 80 e7 76 67 
e9 9d 99 ab f0 52 5d 07 58 66 0f 37 52 65 5b 0f 
25 b8 df 84 31 d9 a8 ff 77 c1 6c 12 a0 a5 12 2a 
9f 0b f7 cf d5 a2 66 a3 5c 15 9f 99 12 08 b9 03 
16 ff 44 4f 3e 0b 6b d0 e9 3b 8a 7a 24 48 e9 57 
e3 dd a6 cf cf 22 66 b1 06 01 3a c4 68 08 d3 b3 
88 7b 3b 00 34 4b aa c9 53 0b 4c e7 08 fc 32 b6 

# ---------------------------------
# RSASSA-PSS Signature Example 10.1
# ---------------------------------

# Message to be signed:
88 31 77 e5 12 6b 9b e2 d9 a9 68 03 27 d5 37 0c 
6f 26 86 1f 58 20 c4 3d a6 7a 3a d6 09 

# Salt:
04 e2 15 ee 6f f9 34 b9 da 70 d7 73 0c 87 34 ab 
fc ec de 89 

# Signature:
82 c2 b1 60 09 3b 8a a3 c0 f7 52 2b 19 f8 73 54 
06 6c 77 84 7a bf 2a 9f ce 54 2d 0e 84 e9 20 c5 
af b4 9f fd fd ac e1 65 60 ee 94 a1 36 96 01 14 
8e ba d7 a0 e1 51 cf 16 33 17 91 a5 72 7d 05 f2 
1e 74 e7 eb 81 14 40 20 69 35 d7 44 76 5a 15 e7 
9f 01 5c b6 6c 53 2c 87 a6 a0 59 61 c8 bf ad 74 
1a 9a 66 57 02 28 94 39 3e 72 23 73 97 96 c0 2a 
77 45 5d 0f 55 5b 0e c0 1d df 25 9b 62 07 fd 0f 
d5 76 14 ce f1 a5 57 3b aa ff 4e c0 00 69 95 16 
59 b8 5f 24 30 0a 25 16 0c a8 52 2d c6 e6 72 7e 
57 d0 19 d7 e6 36 29 b8 fe 5e 89 e2 5c c1 5b eb 
3a 64 75 77 55 92 99 28 0b 9b 28 f7 9b 04 09 00 
0b e2 5b bd 96 40 8b a3 b4 3c c4 86 18 4d d1 c8 
e6 25 53 fa 1a f4 04 0f 60 66 3d e7 f5 e4 9c 04 
38 8e 25 7f 1c e8 9c 95 da b4 8a 31 5d 9b 66 b1 
b7 62 82 33 87 6f f2 38 52 30 d0 70 d0 7e 16 66 

# ---------------------------------
# RSASSA-PSS Signature Example 10.2
# ---------------------------------

# Message to be signed:
dd 67 0a 01 46 58 68 ad c9 3f 26 13 19 57 a5 0c 
52 fb 77 7c db aa 30 89 2c 9e 12 36 11 64 ec 13 
97 9d 43 04 81 18 e4 44 5d b8 7b ee 58 dd 98 7b 
34 25 d0 20 71 d8 db ae 80 70 8b 03 9d bb 64 db 
d1 de 56 57 d9 fe d0 c1 18 a5 41 43 74 2e 0f f3 
c8 7f 74 e4 58 57 64 7a f3 f7 9e b0 a1 4c 9d 75 
ea 9a 1a 04 b7 cf 47 8a 89 7a 70 8f d9 88 f4 8e 
80 1e db 0b 70 39 df 8c 23 bb 3c 56 f4 e8 21 ac 

# Salt:
8b 2b dd 4b 40 fa f5 45 c7 78 dd f9 bc 1a 49 cb 
57 f9 b7 1b 

# Signature:
14 ae 35 d9 dd 06 ba 92 f7 f3 b8 97 97 8a ed 7c 
d4 bf 5f f0 b5 85 a4 0b d4 6c e1 b4 2c d2 70 30 
53 bb 90 44 d6 4e 81 3d 8f 96 db 2d d7 00 7d 10 
11 8f 6f 8f 84 96 09 7a d7 5e 1f f6 92 34 1b 28 
92 ad 55 a6 33 a1 c5 5e 7f 0a 0a d5 9a 0e 20 3a 
5b 82 78 ae c5 4d d8 62 2e 28 31 d8 71 74 f8 ca 
ff 43 ee 6c 46 44 53 45 d8 4a 59 65 9b fb 92 ec 
d4 c8 18 66 86 95 f3 47 06 f6 68 28 a8 99 59 63 
7f 2b f3 e3 25 1c 24 bd ba 4d 4b 76 49 da 00 22 
21 8b 11 9c 84 e7 9a 65 27 ec 5b 8a 5f 86 1c 15 
99 52 e2 3e c0 5e 1e 71 73 46 fa ef e8 b1 68 68 
25 bd 2b 26 2f b2 53 10 66 c0 de 09 ac de 2e 42 
31 69 07 28 b5 d8 5e 11 5a 2f 6b 92 b7 9c 25 ab 
c9 bd 93 99 ff 8b cf 82 5a 52 ea 1f 56 ea 76 dd 
26 f4 3b aa fa 18 bf a9 2a 50 4c bd 35 69 9e 26 
d1 dc c5 a2 88 73 85 f3 c6 32 32 f0 6f 32 44 c3 

# ---------------------------------
# RSASSA-PSS Signature Example 10.3
# ---------------------------------

# Message to be signed:
48 b2 b6 a5 7a 63 c8 4c ea 85 9d 65 c6 68 28 4b 
08 d9 6b dc aa be 25 2d b0 e4 a9 6c b1 ba c6 01 
93 41 db 6f be fb 8d 10 6b 0e 90 ed a6 bc c6 c6 
26 2f 37 e7 ea 9c 7e 5d 22 6b d7 df 85 ec 5e 71 
ef ff 2f 54 c5 db 57 7f f7 29 ff 91 b8 42 49 1d 
e2 74 1d 0c 63 16 07 df 58 6b 90 5b 23 b9 1a f1 
3d a1 23 04 bf 83 ec a8 a7 3e 87 1f f9 db 

# Salt:
4e 96 fc 1b 39 8f 92 b4 46 71 01 0c 0d c3 ef d6 
e2 0c 2d 73 

# Signature:
6e 3e 4d 7b 6b 15 d2 fb 46 01 3b 89 00 aa 5b bb 
39 39 cf 2c 09 57 17 98 70 42 02 6e e6 2c 74 c5 
4c ff d5 d7 d5 7e fb bf 95 0a 0f 5c 57 4f a0 9d 
3f c1 c9 f5 13 b0 5b 4f f5 0d d8 df 7e df a2 01 
02 85 4c 35 e5 92 18 01 19 a7 0c e5 b0 85 18 2a 
a0 2d 9e a2 aa 90 d1 df 03 f2 da ae 88 5b a2 f5 
d0 5a fd ac 97 47 6f 06 b9 3b 5b c9 4a 1a 80 aa 
91 16 c4 d6 15 f3 33 b0 98 89 2b 25 ff ac e2 66 
f5 db 5a 5a 3b cc 10 a8 24 ed 55 aa d3 5b 72 78 
34 fb 8c 07 da 28 fc f4 16 a5 d9 b2 22 4f 1f 8b 
44 2b 36 f9 1e 45 6f de a2 d7 cf e3 36 72 68 de 
03 07 a4 c7 4e 92 41 59 ed 33 39 3d 5e 06 55 53 
1c 77 32 7b 89 82 1b de df 88 01 61 c7 8c d4 19 
6b 54 19 f7 ac c3 f1 3e 5e bf 16 1b 6e 7c 67 24 
71 6c a3 3b 85 c2 e2 56 40 19 2a c2 85 96 51 d5 
0b de 7e b9 76 e5 1c ec 82 8b 98 b6 56 3b 86 bb 

# ---------------------------------
# RSASSA-PSS Signature Example 10.4
# ---------------------------------

# Message to be signed:
0b 87 77 c7 f8 39 ba f0 a6 4b bb db c5 ce 79 75 
5c 57 a2 05 b8 45 c1 74 e2 d2 e9 05 46 a0 89 c4 
e6 ec 8a df fa 23 a7 ea 97 ba e6 b6 5d 78 2b 82 
db 5d 2b 5a 56 d2 2a 29 a0 5e 7c 44 33 e2 b8 2a 
62 1a bb a9 0a dd 05 ce 39 3f c4 8a 84 05 42 45 
1a 

# Salt:
c7 cd 69 8d 84 b6 51 28 d8 83 5e 3a 8b 1e b0 e0 
1c b5 41 ec 

# Signature:
34 04 7f f9 6c 4d c0 dc 90 b2 d4 ff 59 a1 a3 61 
a4 75 4b 25 5d 2e e0 af 7d 8b f8 7c 9b c9 e7 dd 
ee de 33 93 4c 63 ca 1c 0e 3d 26 2c b1 45 ef 93 
2a 1f 2c 0a 99 7a a6 a3 4f 8e ae e7 47 7d 82 cc 
f0 90 95 a6 b8 ac ad 38 d4 ee c9 fb 7e ab 7a d0 
2d a1 d1 1d 8e 54 c1 82 5e 55 bf 58 c2 a2 32 34 
b9 02 be 12 4f 9e 90 38 a8 f6 8f a4 5d ab 72 f6 
6e 09 45 bf 1d 8b ac c9 04 4c 6f 07 09 8c 9f ce 
c5 8a 3a ab 10 0c 80 51 78 15 5f 03 0a 12 4c 45 
0e 5a cb da 47 d0 e4 f1 0b 80 a2 3f 80 3e 77 4d 
02 3b 00 15 c2 0b 9f 9b be 7c 91 29 63 38 d5 ec 
b4 71 ca fb 03 20 07 b6 7a 60 be 5f 69 50 4a 9f 
01 ab b3 cb 46 7b 26 0e 2b ce 86 0b e8 d9 5b f9 
2c 0c 8e 14 96 ed 1e 52 85 93 a4 ab b6 df 46 2d 
de 8a 09 68 df fe 46 83 11 68 57 a2 32 f5 eb f6 
c8 5b e2 38 74 5a d0 f3 8f 76 7a 5f db f4 86 fb 

# ---------------------------------
# RSASSA-PSS Signature Example 10.5
# ---------------------------------

# Message to be signed:
f1 03 6e 00 8e 71 e9 64 da dc 92 19 ed 30 e1 7f 
06 b4 b6 8a 95 5c 16 b3 12 b1 ed df 02 8b 74 97 
6b ed 6b 3f 6a 63 d4 e7 78 59 24 3c 9c cc dc 98 
01 65 23 ab b0 24 83 b3 55 91 c3 3a ad 81 21 3b 
b7 c7 bb 1a 47 0a ab c1 0d 44 25 6c 4d 45 59 d9 
16 

# Salt:
ef a8 bf f9 62 12 b2 f4 a3 f3 71 a1 0d 57 41 52 
65 5f 5d fb 

# Signature:
7e 09 35 ea 18 f4 d6 c1 d1 7c e8 2e b2 b3 83 6c 
55 b3 84 58 9c e1 9d fe 74 33 63 ac 99 48 d1 f3 
46 b7 bf dd fe 92 ef d7 8a db 21 fa ef c8 9a de 
42 b1 0f 37 40 03 fe 12 2e 67 42 9a 1c b8 cb d1 
f8 d9 01 45 64 c4 4d 12 01 16 f4 99 0f 1a 6e 38 
77 4c 19 4b d1 b8 21 32 86 b0 77 b0 49 9d 2e 7b 
3f 43 4a b1 22 89 c5 56 68 4d ee d7 81 31 93 4b 
b3 dd 65 37 23 6f 7c 6f 3d cb 09 d4 76 be 07 72 
1e 37 e1 ce ed 9b 2f 7b 40 68 87 bd 53 15 73 05 
e1 c8 b4 f8 4d 73 3b c1 e1 86 fe 06 cc 59 b6 ed 
b8 f4 bd 7f fe fd f4 f7 ba 9c fb 9d 57 06 89 b5 
a1 a4 10 9a 74 6a 69 08 93 db 37 99 25 5a 0c b9 
21 5d 2d 1c d4 90 59 0e 95 2e 8c 87 86 aa 00 11 
26 52 52 47 0c 04 1d fb c3 ee c7 c3 cb f7 1c 24 
86 9d 11 5c 0c b4 a9 56 f5 6d 53 0b 80 ab 58 9a 
cf ef c6 90 75 1d df 36 e8 d3 83 f8 3c ed d2 cc 

# ---------------------------------
# RSASSA-PSS Signature Example 10.6
# ---------------------------------

# Message to be signed:
25 f1 08 95 a8 77 16 c1 37 45 0b b9 51 9d fa a1 
f2 07 fa a9 42 ea 88 ab f7 1e 9c 17 98 00 85 b5 
55 ae ba b7 62 64 ae 2a 3a b9 3c 2d 12 98 11 91 
dd ac 6f b5 94 9e b3 6a ee 3c 5d a9 40 f0 07 52 
c9 16 d9 46 08 fa 7d 97 ba 6a 29 15 b6 88 f2 03 
23 d4 e9 d9 68 01 d8 9a 72 ab 58 92 dc 21 17 c0 
74 34 fc f9 72 e0 58 cf 8c 41 ca 4b 4f f5 54 f7 
d5 06 8a d3 15 5f ce d0 f3 12 5b c0 4f 91 93 37 
8a 8f 5c 4c 3b 8c b4 dd 6d 1c c6 9d 30 ec ca 6e 
aa 51 e3 6a 05 73 0e 9e 34 2e 85 5b af 09 9d ef 
b8 af d7 

# Salt:
ad 8b 15 23 70 36 46 22 4b 66 0b 55 08 85 91 7c 
a2 d1 df 28 

# Signature:
6d 3b 5b 87 f6 7e a6 57 af 21 f7 54 41 97 7d 21 
80 f9 1b 2c 5f 69 2d e8 29 55 69 6a 68 67 30 d9 
b9 77 8d 97 07 58 cc b2 60 71 c2 20 9f fb d6 12 
5b e2 e9 6e a8 1b 67 cb 9b 93 08 23 9f da 17 f7 
b2 b6 4e cd a0 96 b6 b9 35 64 0a 5a 1c b4 2a 91 
55 b1 c9 ef 7a 63 3a 02 c5 9f 0d 6e e5 9b 85 2c 
43 b3 50 29 e7 3c 94 0f f0 41 0e 8f 11 4e ed 46 
bb d0 fa e1 65 e4 2b e2 52 8a 40 1c 3b 28 fd 81 
8e f3 23 2d ca 9f 4d 2a 0f 51 66 ec 59 c4 23 96 
d6 c1 1d bc 12 15 a5 6f a1 71 69 db 95 75 34 3e 
f3 4f 9d e3 2a 49 cd c3 17 49 22 f2 29 c2 3e 18 
e4 5d f9 35 31 19 ec 43 19 ce dc e7 a1 7c 64 08 
8c 1f 6f 52 be 29 63 41 00 b3 91 9d 38 f3 d1 ed 
94 e6 89 1e 66 a7 3b 8f b8 49 f5 87 4d f5 94 59 
e2 98 c7 bb ce 2e ee 78 2a 19 5a a6 6f e2 d0 73 
2b 25 e5 95 f5 7d 3e 06 1b 1f c3 e4 06 3b f9 8f 

# =============================================
