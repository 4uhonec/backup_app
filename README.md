### Client / server project
Client written in c++, server in python. Client is sending encrypted files for backup over tcp/ip socket, server decrypting it and stores on HDD, while managing 2 SQLite3 database's tables - clients and files.
Scheme of client/server work provided below.
- In client's folder, there is transfer.info file, there are stored:
    1. ip and port of server
    2. client username
    3. list of files to backup
- If registered in the past, there is another file in client's folder, me.info, that contains:
    1. client username
    2. user uuid, that server generated for current client, 8 bits hex format
    3. RSA private key generated in registration attempt, in base 64 format
- If not already registered, client generates RSA pair, sends public key to server, if registration successfull, writes me.info file
- Server uses client's public key to encrypt newly generated symmetric AES key, sends it to client
- Client decrypts AES key, and uses it for file encryption
- Server decrypts files, calculate crc32 checksum and veryfy it with client
- If checksum isn't verified for 4 attempts, file is deleted from database and from HDD on the server side

##### Request header's structure:
- **client_id** 16 bytes
- **client version** 1 byte
- **operation code** 2 bytes
- **payload size** 4 bytes
- 
**Requests opcodes and payload:**
- 1025 registration request (client_name)
- 1026 sent public key (client_name, pub_key)
- 1027 reconnect request (client_name)    <---if me.info presents in clients folder
- 1028 sending file (file_size, filename, encrypted_file)
- 1029 CRC checksum ok (filename)
- 1030 CRC checksum not ok (filename)
- 1031 CRC checksum not ok for 4th time, abort operation (filename)

##### Response header's structure:
- **server_version** 1 byte
- **opcode** 2 bytes
- **payload size** 4 bytes

**Response opcodes and payload**:
- 2100 registration successful (client_id)
- 2101 registration failed
- 2102 got public key, sending encrypted AES (client_id, encrypted_aes_key)
- 2103 got file, sending CRC checksum (client_id, encrypted_file_size, filename, crc)
- 2104 message received, as a response to 1029, 1030 and 1031 requests (client_id)
- 2105 reconnect approved, sending encrypted AES, as response to 1027 (client_id, encrypted_aes_key)
- 2106 reconnect rejected, client not registered or does not have correct public key, after receiveing this client must register 1025 (client_id)
- 2107 general error
