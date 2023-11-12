#include "constants.h"
#include "format_utils.h"
#include "cypher.h"
#include <string>
#include <vector>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class Client{
    public:
        Client();
        ~Client();
        void start();

    private:
        std::string ip;
        std::string port;
        std::string client_name;
        unsigned char* client_id;
        std::string private_key;
        std::string aes_key;
        //aes  (that we get from server?)
        bool connected;
        bool registered;// TODO maybe remove bool registered, unused?
        std::vector<std::string> filelist;
        boost::asio::io_context io_context;
        tcp::socket socket;
        AES aes;
        RSA rsa;

        void write_header(uint16_t code, uint32_t payload_size, unsigned char* data);
        ResponseHeader* read_header();
        bool read_info_file();
        bool read_id_file();
        void write_id_file();
        bool file_exists(std::string filename);
        bool reconnect();
        void receive_payload(unsigned char* payload, unsigned int payload_size);
        bool register_client();
        bool exchange_keys(const unsigned short opcode);
        bool send_file(std::string filename, int i);
        bool send_public_key();
        void send_crc_message(std::string filename, unsigned short opcode);

        void print_bin(const unsigned char* data, uint16_t len); //TODO remove, for debug only
};
