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
        target += ' '
        str = arr[1]
    end
    target
    end
end

class Integer
    def tls_prf(secret = '', label = '', seed = '', hash_methods = 'SHA256')
        return self.tls_P_hash(secret, label + seed, hash_methods)
    end

    def tls_P_hash(secret='', seed = '', hash_methods = 'SHA256')
        t = self.to_f / 32
        t = t.ceil
        ret = ''

        a = seed
        t.times do |i|
            a = OpenSSL::HMAC.send("digest", hash_methods, secret, a)
            ret << OpenSSL::HMAC.send("digest", hash_methods, secret, a + seed)
        end
        return ret[0, self]
    end
end
