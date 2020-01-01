require 'openssl'
require_relative '../encrypt_handler/prf'

messgae = "5f 0c b8 76 7d 52 e9 fd 8c f8
a6 17 e0 24 e2 41 68 fc e6 9c db f3 93 68 50 06
9e 7c 99 d9 c5 be 5a 3a 9e e9 2b 4f 15 3f 2e b4
d9 12 e6 ab fe dc 78 5f 38 bf 01 0a 10 08 f1 37
f9 58 c6 5b 15 71 7b fc ac b2 76 7d 3c 82 59 41
3d 3a 0d 41 a9 60 21 bb 9e 61 cc db b7 ce 0e a4
89 ad f0 88 c7 43 31 56 53 84 0a a7 11 3d 08 ae
70 03 19 52 91 6e 4b 03 26 7c 62 ae d6 40 d6 e3
3d 5c 26 09 4a b8 0d 8f ce 92 ef 71 0f 98 76 fb
57 f6 e5 84 c1 9e 24 9f 24 f8 ce 66 34 8b 58 75
9b 67 96 23 b7 2a 2e 5c e0 9e 3f 0c c9 d5 1d 91
f4 65 4d 8a 13 e4 3f bf 91 c5 87 ee 16 22 65 26
f9 c0 6b e1 72 8f 60 53 ce 76 72 e4 32 57 48 54
ae f7 56 41 87 d7 93 61 1a 7b 7a 35 a4 2d 72 cb
c1 f2 39 2f 13 ef 92 ac 6c 54 7e ab ba ce 7a 72
da 51 79 8d a1 bd 3c 93 ba 1b 9e a7 e7 2b a4 fc
3a 98 30 6b b8 24".to_binary

rsa = OpenSSL::PKey::RSA.new File.read("C:\\Users\\ayanamists\\.babun\\cygwin\\home\\ayanamists\\my_ssl_in_ruby\\certificate\\key.pem")
puts rsa.private_decrypt(messgae).to_hex
