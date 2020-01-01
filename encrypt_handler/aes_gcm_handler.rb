require_relative 'encrypt_message_handler'
require 'pp'

class AES_CGM_Handler
    include EncryptMessageHandler
    attr_accessor :send_cipher, :recv_cipher, :send_implicit, :recv_implicit,
    :send_seq_num, :recv_seq_num
    def initialize(server_random, client_random, certificate = '', length = 0, 
        usage = 'client', version_major = 0x03, version_minor = 0x03)
        if block_given?
            @master = yield
            @version = [0x03, 0x03]
        else
            super(server_random, client_random, certificate)
        end
        # the nonce of AES_GCM is defined by:
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # +  0  1  2  3 | 0  1  2  3  4  5  6  7    +
        # +     salt    |     nonce_explicit        +
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # salt is server_write_iv or client_write_iv, so you need 4 * 2
        # and length need to /8(bit->byte) and * 2(both server and client), so it's length/4
        key_block = (length/4 + 4 * 2).tls_prf(@master, "key expansion", server_random + client_random)
        arr = key_block.unpack "a#{length/8}a#{length/8}a4a4"
        client_write_key = arr[0]
        server_write_key = arr[1]
        client_write_iv = arr[2]
        server_write_iv = arr[3]

        @send_cipher = OpenSSL::Cipher::AES.new(length, :GCM).encrypt
        @recv_cipher = OpenSSL::Cipher::AES.new(length, :GCM).decrypt
        if usage == 'client'
            @send_cipher.key = client_write_key
            @send_implicit = client_write_iv
            @recv_cipher.key = server_write_key
            @recv_implicit = server_write_iv
        elsif usage == 'server'
            @send_cipher.key = server_write_key
            @send_implicit = server_write_iv
            @recv_cipher.key = client_write_key
            @recv_implicit = client_write_iv
        else
            raise "AES_GCM_HANDLER: BAD_ARGUMENT"
        end

        @send_seq_num = 0
        @recv_seq_num = 0
    end

    def send_encrypt(type = 22, seqence = '')
        nonce_explicit = OpenSSL::Random.random_bytes(8)
        nonce = @send_implicit + nonce_explicit
        @send_cipher.iv = nonce
        length = seqence.length
        #the handle of seq_num may be wrong
        @send_cipher.auth_data = [0, @send_seq_num,
            type, @version[0], @version[1], 0 ,length].pack("NNCCCCC")
        puts @send_seq_num
        encrypt = @send_cipher.update(seqence) + @send_cipher.final
        encrypt = encrypt + @send_cipher.auth_tag
        encrypt = nonce_explicit + encrypt
        return encrypt
        @send_seq_num += 1
    end

    def recv_decrypt(type = 22, sequence = '', seq_num = 0)
        if seq_num != 0
            @recv_seq_num = seq_num
        end
        template = 'a8a*'
        arr = sequence.unpack(template)
        nonce_explicit = arr[0]
        length = sequence.length - 8 - 16
        sequence = arr[1]
        encrypted = sequence[0, sequence.length - 16]
        @recv_cipher.auth_tag = sequence[sequence.length - 16, sequence.length]
        @recv_cipher.iv = @recv_implicit + nonce_explicit
        @recv_cipher.auth_data =
            [0, @recv_seq_num, type ,@version[0], @version[1], 0 ,length].pack("NNCCCCC")
        decrypt =  @recv_cipher.update(encrypted) + @recv_cipher.final
        #decrypt = @recv_cipher.update(encrypted) + @recv_cipher.final
        return decrypt
    end
end