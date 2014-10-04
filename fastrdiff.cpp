#include <iostream>
#include <stdint.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <stdlib.h>

using namespace std;


int read_int(int file_handle, int32_t* int_ptr) {
    int32_t integer_value = 0;

    int read_result = read(file_handle, (char*)&integer_value, sizeof(integer_value));
  
    if (read_result <= 0) {
	return 0;
    }

    // convert big endian to little endian 
    integer_value = be32toh(integer_value);

    // return value via ptr
    *int_ptr = integer_value; 

    return 1;
}

bool read_signature_file() {
    string file_path = "/root/broken_rdiff/extracted_backup_34bdf94b-43eb-4491-bc65-196d8f624d48.signature";
    int file_handle = open(file_path.c_str(), O_RDONLY);

    if (!file_handle) {
	std::cout<<"Can't open signature file"<<endl;
	return false;	
    } 

    int32_t RS_SIG_MAGIC = 0x72730136;
    int32_t file_signature_from_file = 0;
    int32_t blocksize_from_file = 0;
    int32_t md4_truncation_from_file = 0;

    read_int(file_handle, &file_signature_from_file);

    if (file_signature_from_file != RS_SIG_MAGIC) {
	std::cout<<"Can't find signature magic number"<<endl;
	return false;
    }

    read_int(file_handle, &blocksize_from_file);

    if (blocksize_from_file > 0 && blocksize_from_file % 2 == 0) {
	cout<<"We read block size:"<<blocksize_from_file<<endl;	
    } else {
	std::cout<<"Block size readed from signature is broken because it's null or it's not an pow of 2: "<<blocksize_from_file<<endl;
	return false;
    }

    read_int(file_handle, &md4_truncation_from_file);

    if (md4_truncation_from_file < 1 or md4_truncation_from_file > 16) {
	cout<<"Truncation is: "<<md4_truncation_from_file<<endl;
	return false;
    }

    cout<<"Truncation for md4 is: "<<md4_truncation_from_file<<endl;
  
    char* md4_checksumm_buffer = (char*)malloc(sizeof(uint32_t) * md4_truncation_from_file);

    if (!md4_checksumm_buffer) {
	std::cout<<"Can't allocate buffer"<<endl;
	return false;
    }

    long long unsigned int offset = 0;
    while (true) {
	int32_t weak_checksumm = 0;

	int read_result = read_int(file_handle, &weak_checksumm);

	if (!read_result) {
	    break;
	}

	read_result = read(file_handle, md4_checksumm_buffer, md4_truncation_from_file);
	if (read_result <= 0) {
	    break;
	}

	printf("weak: %x offset: %lld\n", weak_checksumm, offset);
	// append_list(weak_checksumm, md4_checksumm_buffer, offset)
	offset += blocksize_from_file; 
    }

    free(md4_checksumm_buffer);
 
    // rollsum, md4 signature, offset
    return true;
}

int main() {
    read_signature_file(); 

    return 0;
}
