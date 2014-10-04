#include <iostream>
#include <stdint.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <endian.h>

using namespace std;

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

    pread(file_handle, (char*)&file_signature_from_file, sizeof(file_signature_from_file), 0);

    // convert from big endian to little endian
    file_signature_from_file = be32toh(file_signature_from_file);

    if (file_signature_from_file != RS_SIG_MAGIC) {
	std::cout<<"Can't find signature magic number"<<endl;
	return false;
    }

    pread(file_handle, (char*)&blocksize_from_file, sizeof(blocksize_from_file), 4);
    blocksize_from_file = be32toh(blocksize_from_file);

    if (blocksize_from_file > 0 && blocksize_from_file % 2 == 0) {
	cout<<"We read block size:"<<blocksize_from_file<<endl;	
    } else {
	std::cout<<"Block size readed from signature is broken because it's null or it's not an pow of 2: "<<blocksize_from_file<<endl;
	return false;
    }

    pread(file_handle, (char*)&md4_truncation_from_file, sizeof(md4_truncation_from_file), 8);
    md4_truncation_from_file = be32toh(md4_truncation_from_file);

    if (md4_truncation_from_file < 1 or md4_truncation_from_file > 16) {
	cout<<"Trunkation is: "<<md4_truncation_from_file<<endl;
	return false;
    }

    cout<<"Trucation for md4 is: "<<md4_truncation_from_file<<endl;
    
    // rollsum, md4 signature, offset
    return true;
}

int main() {
    read_signature_file(); 

    return 0;
}
