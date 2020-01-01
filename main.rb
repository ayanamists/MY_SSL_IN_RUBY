require 'openssl'
require 'socket'
require_relative 'encrypt_handler/aes_gcm_handler'
require_relative 'record/handshake'
include Socket::Constants

client_hello = ClientHello.new
str_clinet_hello = client_hello.make
sock = Socket.new(AF_INET, SOCK_STREAM, 0)
sockaddr = Socket.pack_sockaddr_in( 443, 'baidu.com' )
sock.connect(sockaddr)
sock.write(str_clinet_hello)
rec = sock.recv(64000)
#puts rec.length
#puts rec
server_message = Extracter.extract(rec)
puts server_message[0][1].cipher_suites
puts server_message[1][1].certificates[0].subject

#now, we caculate pre-master-key, master-key and aes cipher and iv
puts server_message[0][1].random.make.to_hex
puts client_hello.random.make.to_hex
encrypt_handler = AES_CGM_Handler.new(server_message[0][1].random.make, 
    client_hello.random.make, server_message[1][1].certificates[0], 128)
puts encrypt_handler.master.to_hex
exchange = CilentKeyExchange.new
exchange.encryptPreMasterSercet = encrypt_handler.encrypt_pre_master
str_exchange = exchange.make
sock.write(str_exchange)
bytes = str_clinet_hello + rec + str_exchange
bytes = Extracter.extract(bytes, "tlsPlainText")
change_cipher = ChangeCipherSpec.new
str_change_cipher = change_cipher.make
fin = Finished.new('client', encrypt_handler.master ,bytes)
str_fin = fin.make do |i|
    encrypt_handler.send_encrypt(22, i)
end
puts str_fin.to_hex
sock.write(str_change_cipher + str_fin)
sleep(1)
sock.close()
