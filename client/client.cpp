#include "client.h"
#include "base64wrapper.h"
#include <boost/crc.hpp>
#include <fstream>
#include <iostream>
#include <cstring>

using std::cout, std::endl;
using boost::asio::ip::tcp;

Client::Client() : socket(io_context){
    this->registered = false;
    this->connected = false;
    this->client_id = new unsigned char[CLIENT_ID_SIZE];
    memset(this->client_id, 0, CLIENT_ID_SIZE);

    if (!read_info_file()) {
        cout << "Error reading " << INFO_FILE << endl;
        return;
    }



    try {
        tcp::resolver resolver(io_context);
        tcp::endpoint endpoint = *resolver.resolve({ this->ip, this->port }).begin();
        socket.connect(endpoint);
        cout << "Connected" << endl;
    }
    catch (std::exception& e) {
        cout << "Error: connection failed" << endl;
    }
}

Client::~Client() {
    if (socket.is_open()) {
        cout << "Closing connection...";
        socket.close();
    }
}

void Client::start(){// TODO delete data pointers after each stage
    if (file_exists(ID_FILE) && read_id_file()) {//try to reconnect
        rsa.set_private_key(this->private_key);
        connected = reconnect();
    }
    if (!connected) {
        rsa.generate_key();
        this->private_key = rsa.get_private_key();
        connected = register_client();
        if (!connected) {
            cout << "Registration failed, exit" << endl;
            return;
        }
        write_id_file();
    }

    for (std::string file : filelist) {
        for (int i = 0; i < 4; i++) {
            if (file.size() > MAX_STRING_SIZE) {
                cout << "Filename is larger than 255 characters" << endl;
                break;
            }
            if(!file_exists(file)){
                cout << "File " << file << " does not exist" << endl;
                break;
            }
            bool sent = send_file(file, i);
            if (sent)
                break;
        }
    }
}

bool Client::read_info_file() {
    if (file_exists(INFO_FILE)) {
        try {
            std::string line, port_str;
            std::ifstream file(INFO_FILE);

            std::getline(file, line);
            size_t pos = line.find(':');
            Client::ip = line.substr(0, pos);
            Client::port = line.substr(pos + 1);
            std::getline(file, this->client_name);
            while (std::getline(file, line)) {
                Client::filelist.push_back(line);
            }

            return true;
        }
        catch (std::exception& e) {//TODO can print error message
            cout << "Error reading " << INFO_FILE << endl;
            return false;
        }
    }
    else {
        cout << "Error: can't find file" << INFO_FILE << endl;
        return false;
    }
}

bool Client::read_id_file() {
    try {
        std::string line;
        std::ifstream file(ID_FILE);
        std::getline(file, line);
        if (this->client_name.compare(line) != 0) {
            return false; //client name in transfer.info and me.info are different
        }
        std::getline(file, line);
        if (line.empty()) 
            return false;
        if(!parse_id_to_bytes(line, this->client_id))
            return false;//failed to read id/id is of wrong length
        std::getline(file, line);
        if (line.empty())
            return false;
        this->private_key = Base64Wrapper::decode(line);//TODO load this private key to rsa
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool Client::file_exists(std::string filename) {
    if (FILE* file = fopen(filename.c_str(), "r")) {
        fclose(file);
        return true;
    }
    else {
        return false;
    }
}

void Client::write_id_file() {
    try {
        std::ofstream file(ID_FILE);
        file << this->client_name << endl;
        std::string uuid;
        parse_bytes_to_id(this->client_id, CLIENT_ID_SIZE, &uuid);
        file << uuid << endl;
        file << Base64Wrapper::encode(this->private_key);//TODO replace this.privkey to rsa
    }
    catch (const std::exception&) {
        cout << "Error writing " << ID_FILE << endl;
    }
}

void Client::write_header(const uint16_t code, const uint32_t payload_size, unsigned char* data) {
    unsigned int index = 0;
    for (int i = 0; i < CLIENT_ID_SIZE; i++) {
        data[i] = this->client_id[i];
    }
    index += CLIENT_ID_SIZE;
    data[index++] = CLIENT_VERSION;
    l2b_2bytes(data, code, index);
    l2b_4bytes(data, payload_size, index);
}

ResponseHeader* Client::read_header() {
    ResponseHeader* header = new ResponseHeader();//TODO remove header pointer in parent function?
    try {
        unsigned char* data = new unsigned char[RESPONSE_HEADER_SIZE];
        size_t len = boost::asio::read(this->socket, boost::asio::buffer(data, RESPONSE_HEADER_SIZE), boost::asio::transfer_exactly(RESPONSE_HEADER_SIZE));
        header->version = data[0];
        unsigned int index = 1;
        header->code = b2l_2bytes(data, index);
        header->payload_size = b2l_4bytes(data, index);
        delete[] data;
        return header;
    }
    catch (const std::exception&) {
        cout << "Error receiving header from server" << endl;
        return nullptr;
    }
}

bool Client::reconnect() {
    cout << "Trying to reconnect..." << endl;
    return exchange_keys(OP_REQUEST_RECONNECT);
}

bool Client::register_client() {
    cout << "Trying to connect..." << endl;
    return exchange_keys(OP_REQUEST_REGISTRATION);
}

bool Client::send_public_key() {
    cout << "Sending public key..." << endl;
    const size_t request_size = REQUEST_HEADER_SIZE + MAX_STRING_SIZE + PUBLIC_KEY_SIZE;
    unsigned char data[request_size];
    std::string name = fill_zeroes(this->client_name);
    write_header(OP_REQUEST_SEND_PUBLIC_KEY, MAX_STRING_SIZE + PUBLIC_KEY_SIZE, data);
    std::memcpy(data + REQUEST_HEADER_SIZE, name.data(), name.size());
    std::memcpy(data + REQUEST_HEADER_SIZE + MAX_STRING_SIZE, rsa.get_public_key().data(), PUBLIC_KEY_SIZE);
    try {
        size_t len = boost::asio::write(this->socket, boost::asio::buffer(data, request_size));
        cout << "Sent " << len << " bytes, public key" << endl;
    }
    catch (const std::exception&) {
        cout << "Error sending public key" << endl;
        return false;
    }

}

bool Client::exchange_keys(const unsigned short opcode) {
    cout << "Exchanging keys" << endl;
    const size_t request_size = REQUEST_HEADER_SIZE + MAX_STRING_SIZE;
    unsigned char data[request_size];
    if(opcode == OP_REQUEST_RECONNECT || opcode == OP_REQUEST_REGISTRATION){
        write_header(opcode, MAX_STRING_SIZE, data); 
    }
    else {
        cout << "Error building connect request, wrong opcode" << endl;
    }
    
    std::string name = fill_zeroes(this->client_name);
    std::memcpy(data + REQUEST_HEADER_SIZE, name.data(), name.size());
    try {
        size_t len = boost::asio::write(this->socket, boost::asio::buffer(data, request_size));
        cout << "Sent " << len << " bytes, connect/reconnect request" << endl;

        ResponseHeader* header = read_header();
        cout << header->code << " request opcode" << endl; //TODO remove
        cout << int(header->version) << " version" << endl; //TODO remove

        if (header->code == OP_RESPONSE_REGISTRATION_SUCCESS) {
            cout << "Registration succeeded" << endl; //TODO remove
            unsigned char* payload_id = new unsigned char[header->payload_size];
            receive_payload(payload_id, header->payload_size);
            cout << "Id received" << endl; //TODO remove
            for (size_t i = 0; i < header->payload_size; ++i) {
                this->client_id[i] = payload_id[i];
            }
            
            cout << "Client successfully registered" << endl;
            bool sent = send_public_key();
            if (!sent) {
                return false;
            }
            header = read_header();
        }
        else if (header->code == OP_RESPONSE_REGISTRATION_FAILED || header->code == OP_RESPONSE_GENERAL_ERROR) {
            unsigned char* payload_id = new unsigned char[header->payload_size];
            receive_payload(payload_id, header->payload_size);
            cout << "Registration failed, 2101" << endl;
            delete header;
            return false;
        }
        if (header->code == OP_RESPONSE_RECONNECT_APPROVED_SENDING_AES || header->code == OP_RESPONSE_GOT_PUBLIC_SENDING_AES) {// reconnect approved, receive aes key
            try {
                unsigned char* payload = new unsigned char[header->payload_size];
                unsigned char* aes_encrypted = new unsigned char[header->payload_size - CLIENT_ID_SIZE];
                receive_payload(payload, header->payload_size);
                std::memcpy(this->client_id, payload, CLIENT_ID_SIZE);  //TODO move this to row 193...
                std::memcpy(aes_encrypted, payload + CLIENT_ID_SIZE, header->payload_size - CLIENT_ID_SIZE);
                //now we need to decrypt aes, save it in this->aes
                
                this->aes_key = rsa.decrypt(reinterpret_cast<char*>(aes_encrypted), header->payload_size - CLIENT_ID_SIZE);
                aes.set_key(reinterpret_cast<unsigned char*>(this->aes_key.data()), this->aes_key.size());

                delete[] payload;
                delete[] aes_encrypted;
                delete header;
                return true;
            }
            catch (const std::exception&) {
                cout << "Error receiving AES key while connect/reconnect" << endl;
                delete header;
                return false;
            }
        }
        else {
            unsigned char* payload = new unsigned char[header->payload_size];
            receive_payload(payload, header->payload_size);
            delete header;
            return false;
        }
    }
    catch (const std::exception&) {
        if (opcode == OP_REQUEST_RECONNECT) {
            cout << "Error sending reconnect request" << endl;
        }
        else
            cout << "Error sending registration request" << endl;
        return false;
    }
}

void Client::receive_payload(unsigned char* payload, unsigned int payload_size) {
    try {
        size_t len = boost::asio::read(this->socket, boost::asio::buffer(payload, payload_size), boost::asio::transfer_exactly(payload_size));
    }
    catch (const std::exception&) {
        cout << "Error receiving response payload";
    }
}

//  for 1029, 1030 and 1031 messages
void Client::send_crc_message(std::string filename, unsigned short opcode) {
    cout << "Sending crc message" << endl; //TODO REMOVE, DEBUG
    const size_t message_size = REQUEST_HEADER_SIZE + MAX_STRING_SIZE;
    unsigned char* message = new unsigned char[message_size];
    write_header(opcode, MAX_STRING_SIZE, message);
    std::string fname = fill_zeroes(filename);
    std::memcpy(message + REQUEST_HEADER_SIZE, fname.data(), fname.size());
    try {
        size_t len = boost::asio::write(this->socket, boost::asio::buffer(message, message_size));
        cout << "Sent " << len << " bytes, crc message" << endl;
        ResponseHeader* header = new ResponseHeader();
        header = read_header();
        unsigned char* payload = new unsigned char[header->payload_size];
        receive_payload(payload, header->payload_size);

        if (header->code == OP_RESPONSE_MESSAGE_RECEIVED) {
            cout << "crc message received by server" << endl;
        }
        else {
            cout << "Error, expected 'message received' from server" << endl;
        }
        delete[] payload;
        delete header;
    }
    catch (const std::exception&) {
        cout << "Error sending message" << endl;
    }
}

bool Client::send_file(std::string filename, int i) {
    if (i != 0 && i != 3) {
        cout << "Invalid crc/Bad attempt to send file" << endl;
        send_crc_message(filename, OP_REQUEST_INVALID_CRC);
    }
    try {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        size_t plain_filesize = file.tellg();
        char* plain = new char[plain_filesize];
        file.seekg(0, std::ios::beg);
        file.read(plain, plain_filesize);

        size_t encrypted_filesize = aes.get_encrypted_filesize(filename);
        std::string encrypted_file = aes.encrypt(plain, plain_filesize);
        boost::crc_32_type crc_32;
        crc_32.process_bytes(plain, plain_filesize);
        unsigned int crc = crc_32.checksum();
        cout << "CRC = " << crc << endl;

        const size_t request_size = REQUEST_HEADER_SIZE + FILE_SIZE + MAX_STRING_SIZE + encrypted_filesize;
        unsigned char* data = new unsigned char[request_size];
        write_header(OP_REQUEST_SEND_FILE, request_size - REQUEST_HEADER_SIZE, data);
        unsigned int index = REQUEST_HEADER_SIZE;
        l2b_4bytes(data, encrypted_filesize, index);
        std::string fname = fill_zeroes(filename);
        std::memcpy(data + REQUEST_HEADER_SIZE + FILE_SIZE, fname.data(), fname.size());
        std::memcpy(data + REQUEST_HEADER_SIZE + FILE_SIZE + MAX_STRING_SIZE, encrypted_file.data(), encrypted_filesize);
        boost::asio::write(this->socket, boost::asio::buffer(data, request_size));

        cout << "File sent, waiting for response..." << endl;
        ResponseHeader* header = new ResponseHeader();
        header = read_header();

        if (header->code == OP_RESPONSE_GOT_FILE_WITH_CRC) {
            unsigned char* payload = new unsigned char[header->payload_size];
            receive_payload(payload, header->payload_size);

            unsigned int index = CLIENT_ID_SIZE + FILE_SIZE + MAX_STRING_SIZE;
            unsigned int crc_server = b2l_4bytes(payload, index);
            cout << "server crc = " << crc_server << endl;
            if (crc != crc_server) {
                if (i == 3) {
                    send_crc_message(filename, OP_REQUEST_INVALID_CRC_ABORT);
                    ResponseHeader* header = new ResponseHeader();
                    header = read_header();
                    unsigned char* payload = new unsigned char[header->payload_size];
                    receive_payload(payload, header->payload_size);
                    delete[] payload;
                    delete header;
                }
                return false;
            }
            else {
                cout << "CRC for file " << filename << " matched" << endl;
                return true;
            }
            delete[] payload;
        }
        else {
            unsigned char* payload = new unsigned char[header->payload_size];
            receive_payload(payload, header->payload_size);
            return false;
        }
    }
    catch (const std::exception&) {
        cout << "Error sending file " << filename << endl;
        return false;
    }
}

void Client::print_bin(const unsigned char* data, uint16_t len) {
    for (int i = 0; i < len; i++) {
        cout << int(data[i]) << " ";
    }
    cout << endl;
}