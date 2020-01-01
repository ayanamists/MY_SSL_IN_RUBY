require_relative 'record'

class Handshake < Record
    attr_accessor :record, :handshakeType, :handshakeLength, :handshakeBody
    def initialize
        super
        @tlsPlainText.contentType = 22
    end

    def self.handshake_type
        return {'1' => 'client_hello',
                '2' => 'server_hello',
                '11' => 'server_certificates',
                '14' => 'server_hello_done'}
    end

    def make(encrypt = false)
        template = 
            "C"+ #handshakeType
            "Cn"+ #length
            "a#{@handshakeLength}" #body
        
        arr = [self.handshakeType, 0 ,self.handshakeLength, self.handshakeBody]
        pack = arr.pack template
        @tlsPlainText.fragment = pack
        @tlsPlainText.length = pack.length
        super(encrypt)
    end

    def self.extract(sequence = '') 
        template = 
            "C"+ #handshakeType
            "Cn"+ #length
            "a*" #body
        arr = sequence.unpack(template)
        case arr[0]
        when 1
            return [Handshake.handshake_type["1"] , ClientHello.new(arr[3])]
        when 2
            return [Handshake.handshake_type["2"] , ServerHello.new(arr[3])]
        when 11
            return [Handshake.handshake_type["11"], ServerCertificates.new(arr[3])]
        when 14
            return [Handshake.handshake_type["14"], ServerHelloDone.new(arr[3])]
        else 
            raise("can't handle")
        end
    end
        
end

class ChangeCipherSpec < Record
    def initialize
        super
        @tlsPlainText.contentType = 20
        @tlsPlainText.fragment = [1].pack('C')
        @tlsPlainText.length = @tlsPlainText.fragment.length
    end
end

class ClientHello < Handshake
    attr_accessor :clinetVersion, :random, :session_id,
    :cipher_suites, :compression_methods, :extensions
    def initialize(sequence = '')
        super()
        @handshakeType = 1
        @clinetVersion = 0x0303
        @compression_methods = 0x0100
        if sequence.length == 0
            @random = MyRandom.new
            @session_id = SessionId.new
            @cipher_suites = CipherSuites.new
            @extensions = Extensions.new
        else
        end
    end

    def make
        template = 
            "n"+ #clientVersion
            "a32"+ #random
            "a33"+ #session_id
            "a#{self.cipher_suites.length + 2 }"+ #cipher_suites
            "n"+ #compression_methods
            "a#{self.extensions.length + 2}" #extensions
        
        client_hello = [self.clinetVersion, self.random.make, self.session_id.make,
            self.cipher_suites.make, self.compression_methods, self.extensions.make].pack template
        @handshakeBody = client_hello
        if block_given?
            yield(@handshakeBody)
        end
        @handshakeLength = client_hello.length
        super
    end
end

class ServerHello < Handshake
    attr_accessor :serverVersion, :random, :cipher_suites, :session_id, 
    :compression_methods, :extensions
    def initialize(sequence = '')
        super()
        @serverVersion = 0x0303
        @compression_methods = 0x0100
        if sequence.length == 0
        else
            template = 
                "n"+ #serverVersion
                "a32"+ #random
                "a33"+ #session_id
                "n"+ #cipher_suite
                "n"+ #compression_methods
                "a*" #extensions
            arr = sequence.unpack(template)
            @random = MyRandom.new arr[1]
            @session_id = SessionId.new arr[2]
            @cipher_suites = arr[3]
            @compression_methods = arr[4]
            @extensions = Extensions.new arr[5]
        end
    end
end

class ServerCertificates < Handshake
    attr_accessor :certificatesLength, :certificates
    def initialize(sequence = '')
        super()
        self.handshakeType = 11
        if sequence.length == 0
        else
            template = 
                "Cn"+ #certificatesLength
                "a*" #certificates
            arr = sequence.unpack template
            @certificatesLength = arr[1]
            certificates_meta = arr[2]
            @certificates = []
            #puts @certificatesLength
            while certificates_meta.length != 0
                arr = certificates_meta.unpack("Cna*")
                length = arr[1]
                certificates_meta = arr[2]
                arr = certificates_meta.unpack("a#{length}a*")
                #puts length
                cer = OpenSSL::X509::Certificate.new(arr[0])
                @certificates << cer
                certificates_meta = arr[1]
            end

        end
    end
end

class ServerHelloDone < Handshake
    def initialize(sequence = '')
        super()
        self.handshakeType = 14
    end
end

class CilentKeyExchange < Handshake
    attr_accessor :key_algorithm, :encryptPreMasterSercet
    def initialize(key_algorithm = 'rsa', sequence = '')
        super()
        @handshakeType = 16
        @key_algorithm = key_algorithm
    end

    def make    
        if key_algorithm == 'rsa'
            @handshakeBody =  [encryptPreMasterSercet.length, encryptPreMasterSercet].pack(
                "na#{encryptPreMasterSercet.length}")
            @handshakeLength = @handshakeBody.length
            puts @handshakeLength
        else
        end
        super
    end
end

class Finished < Handshake
    attr_accessor :type, :hash_method, :verfiy_data, :verify_data_length
    def initialize(type = 'client', master_secret = '', handshake_messages = '', sequence = '')
        super()
        @hash_method = 'SHA256'
        self.handshakeType = 20
        @verify_data_length = 12
        @verfiy_data = @verify_data_length.tls_prf(master_secret, 
            "#{type} finished", OpenSSL::Digest.send("digest", @hash_method, handshake_messages))
    end

    def make
        @handshakeBody = @verfiy_data
        @handshakeLength = @verify_data_length
        super(true)
    end
        
end

class MyRandom
    attr_accessor :gmt_unix_time, :random_bytes
    def initialize(sequence = '')
        if sequence.length == 0
            time = Time.new
            @gmt_unix_time = time.to_i
            @random_bytes = OpenSSL::Random.random_bytes(28)
        else 
            template = "Na28"
            arr = sequence.unpack template
            @gmt_unix_time = arr[0]
            @random_bytes = arr[1]
        end
    end

    def make
        template = "Na28"
        return [self.gmt_unix_time, self.random_bytes].pack(template)
    end
end

class SessionId
    attr_accessor :length, :session_id
    def initialize(sequence = '')
        if sequence.length == 0
            @length = 32
            @session_id = OpenSSL::Random.random_bytes(32)
        else
            template = "Ca32"
            arr = sequence.unpack template
            @length = arr[0]
            @random = arr[1]
        end
    end

    def make
        template = "Ca32"
        return [self.length, self.session_id].pack(template)
    end
end

class CipherSuites
    attr_accessor :length, :vector
    def initialize
        @length = 12
        @vector = [0X7a7a, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a]
    end
    def make
        template = "n#{length/2}"
        vec = @vector.pack template
        template = "na#{length}"
        return [length, vec].pack template
    end
end

class Extensions
    attr_accessor :length
    def initialize(sequence = '')
        @length = 0 
    end

    def make
        template="n"
        return [self.length].pack(template)
    end
end
