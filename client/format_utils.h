#pragma once
#include "constants.h"
#include <cstring>
#include <string>
#include <iostream>

class ResponseHeader {
public:
	unsigned char version;
	unsigned short code;
	unsigned int payload_size;
};

std::string fill_zeroes(const std::string input);

//char* fill_zeroes(const std::string& input);

bool parse_id_to_bytes(const std::string& in, unsigned char* out);

unsigned char char_to_byte(char ch);

void parse_bytes_to_id(unsigned char* in, size_t size, std::string* out);

//	ENDIAN UTILITIES
//	BIG TO LITTLE

unsigned short b2l_2bytes(unsigned char* data, unsigned int& index);
unsigned int b2l_4bytes(unsigned char* data, unsigned int& index);

//	LITTLE TO BIG

void l2b_2bytes(unsigned char* data, unsigned short num, unsigned int& index);
void l2b_4bytes(unsigned char* data, unsigned int num, unsigned int& index);
