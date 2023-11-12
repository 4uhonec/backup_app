#pragma once
#include <rsa.h>
#include <osrng.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <string>
#include "constants.h"

class AES {
private:
	unsigned char _key[AES_CBC_KEY_SIZE];
public:
	AES();

	size_t get_encrypted_filesize(std::string file);
	void set_key(unsigned char* key, unsigned int length);
	static unsigned char* generate_key(unsigned char* buffer, unsigned int length);
	const unsigned char* get_key() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);

};

class RSA {
private:
	CryptoPP::AutoSeededRandomPool _rng;
	CryptoPP::RSA::PrivateKey _privateKey;
public:
	RSA();

	void generate_key();
	void set_private_key(std::string private_key);

	std::string get_private_key();

	std::string get_public_key();

	std::string decrypt(const std::string& cipher);
	std::string decrypt(const char* cipher, unsigned int length);
};

