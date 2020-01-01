#encode: US-ASCII
require "zlib"
require 'openssl'
require 'pp'
class String 
    def to_binary
        str = self.clean
        target = ''
        while str.length != 0
            arr = str.unpack("a2a*")
            int = arr[0].hex
            target += [int].pack("C")
            str = arr[1]
        end
        target
    end

    def clean
        target = ''
        self.each_char do |i|
            if /[a-zA-Z0-9]/ =~ i
                target += i
            end
        end
        target
    end

   def to_hex
    str = self
    target = ''
    while str.length != 0
        arr = str.unpack("Ca*")
        int = arr[0]
        if int < 0x10
            target += "0#{int.to_s(16)}"
        else
            target += int.to_s(16)
        end
        #target += ' '
        str = arr[1]
    end
    target
    end
end

key = OpenSSL::Random.random_bytes(16)
nonce = OpenSSL::Random.random_bytes(12)
auth_data = 0x999.to_s(16)

data = "d9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39".to_binary
#puts data
cipher = OpenSSL::Cipher::AES.new(128, :GCM).encrypt
cipher.key = "feffe9928665731c6d6a8f9467308308".to_binary
cipher.iv = "cafebabefacedbaddecaf888".to_binary
cipher.auth_data = "feedfacedeadbeeffeedfacedeadbeef
abaddad2".to_hex
encrypted = cipher.update(data) + cipher.final
#puts encrypted.to_hex

#encrypted = "\xA5z\xBE\xE5\\\x186g\xB164?\xEE\xF4\xA3\x87\xCB|\xF800"
#encrypted = "\x90H\xE7\x94\xA3o\x8E;\xECo\xCB9\x14\xF7\x1F\xCB"
encrypted =  "a5 7a be e5 5c 18 36 67 b1 36 34 3f ee f4 a3 87 cb 7c f8 30 30".to_binary
puts encrypted.length
decipher = OpenSSL::Cipher::AES.new(128, :GCM)
decipher.decrypt
#a= "K\x11\x9D\xFB\xFC\x93\n\xBE\x13\x000\xBDS\xC3\xBFx"
#b = " )\xCA\xE2\xC9\x1D\xE0\x05\xE2\xAEP\xA8"
#puts a.to_hex
#puts b.to_hex
decipher.key =" 4b 11 9d fb fc 93 0a be 13 00 30 bd 53 c3 bf 78".to_binary
decipher.iv = " 20 29 ca e2 c9 1d e0 05 e2 ae 50 a8".to_binary
decipher.auth_data = " 00 00 00 00 00 00 00 01 17 03 03 00 15".to_binary
decipher.auth_tag = " a4 7e 23 0a f2 68 37 8c 4f 33 c8 b5 ba b3 d2 6d".to_binary

decrypted = decipher.update(encrypted) + decipher.final
puts decrypted.to_hex
decrypted = "789c".to_binary + decrypted
in_ = Zlib::Inflate.new
puts in_.inflate(decrypted)
