#include "cypher.h"
#include <filesystem>

AES::AES()
{
	generate_key(_key, AES_CBC_KEY_SIZE);
}

size_t AES::get_encrypted_filesize(std::string file) {
	return (size_t)(ceil(std::filesystem::file_size(file) / static_cast<int>(CryptoPP::AES::BLOCKSIZE)) + 1) * static_cast<int>(CryptoPP::AES::BLOCKSIZE);
}

unsigned char* AES::generate_key(unsigned char* buffer, unsigned int length) {
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(buffer, length);
	return buffer;
}

void AES::set_key(unsigned char* key, unsigned int length) {
	memcpy_s(_key, AES_CBC_KEY_SIZE, key, length);
}

const unsigned char* AES::get_key() const {
	return _key;
}

std::string AES::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, AES_CBC_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AES::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, AES_CBC_KEY_SIZE);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}

RSA::RSA() {}

void RSA::generate_key() {
	_privateKey.Initialize(_rng, RSA_KEY_SIZE);
}

void RSA::set_private_key(std::string private_key) {
	CryptoPP::StringSource ss(private_key, true);
	_privateKey.Load(ss);
}

std::string RSA::get_private_key(){
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

std::string RSA::get_public_key() {
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

std::string RSA::decrypt(const std::string& cipher) {
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

std::string RSA::decrypt(const char* cipher, unsigned int length) {
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}