#include <iostream>
#include <vector>

#include <stdint.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

using namespace std;

long long unsigned int get_file_size(const char* file_name) {
    struct stat st;
    stat(file_name, &st);
    
    return st.st_size;
}

void hexlify(const char* in, unsigned int size, char* out);
void print_md4_summ(char* weak_checksumm, int md4_truncation_length);
int read_int(int file_handle, int32_t* int_ptr);
bool read_signature_file();

typedef struct signature_element { 
    char md4_checksumm[8];
    int32_t weak_checksumm;
    unsigned long long offset; 
} signature_element;

vector<signature_element> signatures_vector;

int main() {
    read_signature_file();

    return 0;
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

    if (md4_truncation_from_file != 8) {
	cout<<"We support only 8byte md4 truncation! Sorry :("<<endl;
	return false;
    }

    cout<<"Truncation for md4 is: "<<md4_truncation_from_file<<endl;
  
    //char* md4_checksumm_buffer = (char*)malloc(md4_truncation_from_file);

    // TODO: пока не ясно как сделать поддержку динамического размера, но я не думаю, что она вообще кому-то нужна
    char md4_checksumm_buffer[8];

    //if (!md4_checksumm_buffer) {
    //	std::cout<<"Can't allocate buffer"<<endl;
    //	return false;
    //}

    unsigned long long file_size = get_file_size(file_path.c_str());

    // Размер одной записи примерно
    // Вычетаем размер хидера и делим на размер одной сигнатуры 
    unsigned long long signatures_count = int ( (file_size - sizeof(uint32_t) * 3) / (sizeof(uint32_t) + md4_truncation_from_file));

    std::cout<<"We calculated approximate signatures number as: "<<signatures_count<<endl;
    // Для ускорения работы с вектором, мы резервируем место под ожидаемое число записей сразу 
    signatures_vector.reserve(signatures_count);

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

	printf("weak: %08x offset: %lld ", weak_checksumm, offset);
	printf("md4: ");
	print_md4_summ(md4_checksumm_buffer, md4_truncation_from_file);
	printf("\n");

	signature_element current_element;
	strncpy(current_element.md4_checksumm, md4_checksumm_buffer, 8);
	current_element.weak_checksumm = weak_checksumm;
	current_element.offset = offset;
	
	signatures_vector.push_back(current_element);
	offset += blocksize_from_file; 
    }

    // rollsum, md4 signature, offset
    return true;
}

void print_md4_summ(char* md4_checksumm, int md4_truncation_length) {
    char output[32];

    hexlify(md4_checksumm, md4_truncation_length, output);
    printf("%s", output);
}

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



// http://tau-itw.wikidot.com/saphe-implementation-common-hexlify-cpp
// Convert to upper-case hex string
void hexlify(const char* in, unsigned int size, char* out)
{
    for (unsigned int i = 0 ; i < size ; ++i) {
        for (int j = 0 ; j < 2 ; ++j) {
            char nib = (char)(( in[i] >> (4-(4*j)) ) & 0xF);
	    
            if (nib < 10) {
                out[(i*2)+j] = nib + '0';
            } else {
		// если добавить A, то получтся в верхнем регистре
                out[(i*2)+j] = nib - 10 + 'a';
            }
        }        
    }
    out[size*2] = 0;
}
