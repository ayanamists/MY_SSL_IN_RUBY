require 'openssl'

class Record
    attr_accessor :tlsPlainText
    def initialize
        gen_table = {}

        #def protocolVersion
        protocolVersion = Class.new do
            attr_accessor :major, :minor
        end

        #def contentType
        contentType = {"change_cipher_spec" => 20, "alert" => 21, 
            "handshake" => 22, "application_data" => 23}
        
        #def tlsPlainText
        tlsPlainText = Class.new do 
            attr_accessor :contentType, :protocolVersion, :length, :fragment
        end
        @tlsPlainText = tlsPlainText.new
        @tlsPlainText.protocolVersion = protocolVersion.new
        @tlsPlainText.protocolVersion.major = 3
        @tlsPlainText.protocolVersion.minor = 3
    end

    def make(encrypt = false)
        if encrypt == true
            puts tlsPlainText.fragment.to_hex
            @tlsPlainText.fragment = yield(@tlsPlainText.fragment)
            @tlsPlainText.length = @tlsPlainText.fragment.length
        end
        template =
            "C"+  #type
            "CC"+ #protocolVersion
            "n"+  #length
            "a#{@tlsPlainText.length}" #fragment
        
        arr = [@tlsPlainText.contentType, @tlsPlainText.protocolVersion.major, 
            @tlsPlainText.protocolVersion.minor, @tlsPlainText.length, @tlsPlainText.fragment ]
        ret = arr.pack template
        return ret
    end

    def self.extract(sequence = "")
        template = 
            "C"+ #type
            "CC" + #protocolVersion
            "n"+ #length
            "a*"
        arr = sequence.unpack template
        template = "a#{arr[3]}a*"
        new_arr = arr[4].unpack template
        gen = new_arr[0]
        ret = new_arr[1]
        case arr[0]
        when 22
            yield(Handshake.extract gen)
        else
            raise("can't handle")
        end
        ret
    end

    def self.extract_tlsPlainText(sequence = '')
        template = 
            "C"+ #type
            "CC" + #protocolVersion
            "n"+ #length
            "a*"
        arr = sequence.unpack template
        template = "a#{arr[3]}a*"
        new_arr = arr[4].unpack template
        gen = new_arr[0]
        ret = new_arr[1]
        case arr[0]
        when 22
            yield(gen)
        else
            raise("can't handle")
        end
        ret
    end
end

class Extracter
    def self.extract(sequence = "", mode = 'all')
        ret_arr = []
        ret_byte = ''
        if mode == 'tlsPlainText'
            while sequence.length != 0
                # Record.extract will yield a pair like 
                # ["type", object]
                sequence = Record.extract_tlsPlainText(sequence) do |i|
                    ret_byte += i
                end
            end
            return ret_byte
        else
            while sequence.length != 0
                # Record.extract will yield a pair like 
                # ["type", object]
                sequence = Record.extract sequence do |i|
                    ret_arr << i
                end
            end
        end
        return ret_arr
    end
end