#pragma once
#include <cstdint>
#include <string>
//   ALL VALUES ARE IN BYTES
//   SYSTEM CONSTANTS

static const unsigned short  BUFFER_SIZE = 1024;
static const unsigned short CLIENT_VERSION = 3;
static const std::string INFO_FILE = "transfer.info";
static const std::string ID_FILE = "me.info";
static const std::string PRIVATE_KEY_FILE = "priv.key";
static const unsigned short MAX_CONNECT_ATTENPTS = 3;
//static const unsigned short MAX_CLIENT_NAME = 100;

//   CRYPTO CONSTANTS

static const unsigned short AES_CBC_KEY_SIZE = 16; //128 bit
static const unsigned short RSA_KEY_SIZE = 1024; //1024 bit

//   HEADER PARTS SIZES

static const unsigned short CLIENT_ID_SIZE = 16;
static const unsigned short VERSION_SIZE = 1;
static const unsigned short CODE_SIZE = 2;
static const unsigned short PAYLOAD_SIZE = 4;

//   PAYLOAD SIZES

static const unsigned short MAX_STRING_SIZE = 255;
static const unsigned short FILE_SIZE = 4;
static const unsigned short PUBLIC_KEY_SIZE = 160;

//   REQUEST CODES

static const unsigned short OP_REQUEST_REGISTRATION = 1025;
static const unsigned short OP_REQUEST_SEND_PUBLIC_KEY = 1026;
static const unsigned short OP_REQUEST_RECONNECT = 1027;
static const unsigned short OP_REQUEST_SEND_FILE = 1028;
static const unsigned short OP_REQUEST_VALID_CRC = 1029;
static const unsigned short OP_REQUEST_INVALID_CRC = 1030;
static const unsigned short OP_REQUEST_INVALID_CRC_ABORT = 1031;

//	RESPONSE CODES

static const unsigned short OP_RESPONSE_REGISTRATION_SUCCESS = 2100;
static const unsigned short OP_RESPONSE_REGISTRATION_FAILED = 2101;
static const unsigned short OP_RESPONSE_GOT_PUBLIC_SENDING_AES = 2102;
static const unsigned short OP_RESPONSE_GOT_FILE_WITH_CRC = 2103;
static const unsigned short OP_RESPONSE_MESSAGE_RECEIVED = 2104;
static const unsigned short OP_RESPONSE_RECONNECT_APPROVED_SENDING_AES = 2105;
static const unsigned short OP_RESPONSE_RECONNECT_NOT_APPROVED = 2106;
static const unsigned short OP_RESPONSE_GENERAL_ERROR = 2107;

static const unsigned short REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE;
static const unsigned short RESPONSE_HEADER_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE;
