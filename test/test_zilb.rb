require 'zlib'
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

a = "hahaha"
puts Zlib::Deflate.deflate(a).to_hex