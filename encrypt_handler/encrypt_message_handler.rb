require 'openssl'
require_relative 'prf'
module EncryptMessageHandler
    attr_accessor :pre_master, :encrypt_pre_master, :master, :version
    def initialize(server_random, client_random, certificate, 
        version_major = 0x03, version_minor = 0x03)
        @version = [version_major, version_minor]
        @pre_master = @version.pack("CC") + OpenSSL::Random.random_bytes(46)
        rsa = OpenSSL::PKey::RSA.new (certificate.public_key)
        puts @pre_master.to_hex
        @encrypt_pre_master = rsa.public_encrypt @pre_master
        @master = 48.tls_prf(@pre_master, "master secret", client_random + server_random)
    end
end