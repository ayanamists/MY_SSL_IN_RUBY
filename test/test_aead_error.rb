require 'openssl'

key = OpenSSL::Random.random_bytes(16)
nonce = OpenSSL::Random.random_bytes(12)
auth_data = 'auth_data'
data = "hello, aes_GCM!"
cipher = OpenSSL::Cipher::AES.new(128, :GCM).encrypt
cipher.key = key
cipher.iv = nonce
encrpyted = cipher.update(data) + cipher.final

decipher = OpenSSL::Cipher::AES.new(128, :GCM).decrypt
decipher.key = key
decipher.iv = nonce
decipher.auth_data = 'auth_data'
decipher.auth_tag = cipher.auth_tag
decrypted = decipher.update(encrpyted) + decipher.final
puts decrypted
