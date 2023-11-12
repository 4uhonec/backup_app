#include "format_utils.h"
#include <sstream>
#include <iomanip>

using std::cout, std::endl;

std::string fill_zeroes(const std::string input) {
	std::string output(MAX_STRING_SIZE, '\0');
	if (input.size() <= output.size()) {
		std::copy(input.begin(), input.end(), output.begin());
	}
	else{
		cout << "In function 'fill_zeroes', input string is too large" << endl;
	}
	return output;
}

/*char* fill_zeroes(const std::string& input) {
	char* output = new char[MAX_STRING_SIZE];

	std::memset(output, '\0', MAX_STRING_SIZE);
	std::strncpy(output, input.c_str(), std::min(MAX_STRING_SIZE, static_cast<unsigned short>(input.size())));

	return output;
}*/

bool parse_id_to_bytes(const std::string& in, unsigned char* out) {
	if (in.size() != CLIENT_ID_SIZE * 2) {
		cout << "Error: wrong id size" << endl;
		return false;
	}

	for (int index = 0; index < in.size() - 1; index += 2) {//TODO check if we get 16bit
		out[index / 2] = (char_to_byte(in[index]) << 4) + char_to_byte(in[index + 1]);
	}

	return true;
}

unsigned char char_to_byte(char ch) {
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		ch = ch + ('a' - 'A');
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	throw std::exception("Char is not hexadecimal");//TODO refactor this so this will run smooth without exception
}

void parse_bytes_to_id(unsigned char* in, size_t size, std::string* out) {
	if (out != nullptr) {
		std::stringstream ss;
		for (size_t i = 0; i < size; ++i) {
			// Write each byte as two hex digits
			ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(in[i]);
		}
		*out = ss.str();
	}
	else
		cout << "Error translating it to hex" << endl;
}

//	ENDIAN UTILITIES

//2 bytes number from little to big endian
void l2b_2bytes(unsigned char* data, unsigned short num, unsigned int& index) {
	unsigned short mask_2bytes = 0x00FF;
	data[index++] = num & mask_2bytes;
	data[index++] = (num >> 8) & mask_2bytes;
}

//4 bytes number from little to big endian
void l2b_4bytes(unsigned char* data, unsigned int num, unsigned int& index) {
	unsigned int mask_4bytes = 0x000000FF;
	for (int i = 0; i < 4; i++) {
		data[index++] = (num >> 8 * i) & mask_4bytes;
	}
}

//2 bytes from big to little endian
unsigned short b2l_2bytes(unsigned char* data, unsigned int& index) {
	unsigned short num = (unsigned short)(data[index + 1] << 8 | data[index]);
	index += 2;
	return num;
}

//4 bytes from big to little endian
unsigned int b2l_4bytes(unsigned char* data, unsigned int& index) {
	unsigned int num = (unsigned int)(data[index + 3] << 24 | data[index + 2] << 16 | data[index + 1] << 8 | data[index]);
	index += 4;
	return num;
}
