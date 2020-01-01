require_relative 'encrypt_handler/aes_gcm_handler'
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
        target += ' '
        str = arr[1]
    end
    target
    end
end

#test_case: 1 
master_secret = "2D1AD6D88DA2FDDDE2CD391807C8357A28A24F4E4256C5DE6A64F671650880902956CAEADAD8CCFEF0F6F7BE2402C703"
client_random = "70 5d b6 a5 f8 2f 40 37 32 11
d1 06 3e 3e 45 4c ef 86 8a 40 09 2a c1 d8 ee df
ad 02 a5 e2 a8 f2"
puts client_random.clean.length
server_random = "5d a4 21 e9 7a 51 41 f4 9c 88
81 ef 97 c4 7c 51 41 f4 4b 7c 15 75 a2 e9 62 25
44 d1 fb c0 83 39"

#test_case: 2
s_r = "5a1b3957e3bd1644e7083e25c64f137ed2803b680e43395a82e5b302b64ba763".to_binary
c_r = "375f5632ba9075b88dd83eeeed4adb427d4011298efb79fb2bf78f4a4b7d9d95".to_binary
m = "2FB179AB70CD4CA2C1285B4B1E294F8F44B7E8DA26B62D00EE35181575EAB04C
4FA11C0DA3ABABB4AF8D09ACB4CCC3CD".to_binary
encrypt_data = "00 00 00 00 00 00 00 01-87 ad 74 ab 12 62 6c 70 
dd 36 e9 a8 c7 1c 17 8f-96 4d 32 39 cb bf b5 d6
af 53 8d d1 af ec ef 2c-f6 8a 8e 3f aa 01 88 41
13 44 53 4b"
#client_encrypter = AES_CGM_Handler.new(server_random.to_binary, client_random.to_binary, '', 128) do 
    master_secret.to_binary
#end
#de = client_encrypter.recv_decrypt(23,encrypt_data.to_binary,1)
#pp de
#e = "c91de005e2ae50a8a57abee55c183667b136343feef4a387cb7cf83030a47e230af268378c4f33c8b5bab3d26d".to_binary

master_secret = "e6 1f e0 c0 26 fc f2 0e b6 6b 21 60 91 56 95 df 3d d2 95 0b 03 e7 f6 cb dd 08 29 6d 85 aa 34 3b f3 26 b7 a5 33 29 48 c3 56 19 d3 b6 4a 02 27 e8"
client_random = "5d a6 fa 1e 13 c8 67 59 6c f5 bf 99 43 be fe c3 b1 78 d2 15 2d 73 f2 cd 3f c8 31 77 9c f1 33 81"
server_random = "c3 66 b1 33 3d a6 2d de 7e 8c 78 72 a3 d4 fe f5 bb db 47 ae 16 8e 92 22 84 06 65 13 50 9a 2e 14"

server_encrypter = AES_CGM_Handler.new(server_random.to_binary, client_random.to_binary, '', 128, "server") do 
    master_secret.to_binary
end

encrypt_data = "2f 25 b7 67 dc f5 0a 8c 0b 38 60 b7 c1 fa d2 fa 3f 1f 3b d7 8b 3b 51 3a 57 67 d4 e5 30 8a 9d 52 0e 1e 4d 56 a0 36 02 5f".to_binary
decrypt_date = server_encrypter.recv_decrypt(22, encrypt_data, 0)