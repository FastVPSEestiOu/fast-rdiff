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

/*
 Команды из дельты можно найти вот здесь: https://github.com/librsync/librsync/blob/master/command.c
*/

/*
 Генерация тест блока данных: 
  rdiff signature --block-size 1048576 /root/broken_rdiff/root.hdd root.hdd.signature
*/

typedef struct signature_element {
    char md4_checksumm[8];
    int32_t weak_checksumm;
    unsigned long long offset;
} signature_element;

void process_file();
unsigned int rs_calc_weak_sum(void const *p, int len);
long long unsigned int get_file_size(const char* file_name);
void hexlify(const char* in, unsigned int size, char* out);
void print_md4_summ(char* weak_checksumm, int md4_truncation_length);
int read_int(int file_handle, int32_t* int_ptr);
bool read_signature_file();

vector<signature_element> signatures_vector;

int main() {
    read_signature_file();

    process_file();

    return 0;
}


void process_file() {
    string file_path = "/root/fastrdiff/root.hdd";
    int file_handle = open(file_path.c_str(), O_RDONLY);

    if (!file_handle) {
        std::cout<<"Can't open signature file"<<endl;
        return;   
    }

    unsigned int block_size = 1048576; 

    void* buffer = malloc(block_size);
    unsigned long long int index = 0;
    while (true) {
	int readed_bytes = read(file_handle, buffer, block_size);

	if (readed_bytes <= 0) {
	    break;
	}

	unsigned int weak_checksumm = rs_calc_weak_sum(buffer, readed_bytes);
	signature_element current_block_checksumm_data = signatures_vector[index];

	// rs_mdfour((unsigned char *) sum, buf, len);

	if (current_block_checksumm_data.weak_checksumm == weak_checksumm) {
	    //std::cout<<"Signature match"<<endl;
	} else {
	    printf("Signature not matched! File weak summ: %08x signature file weak summ: %08x",
		weak_checksumm, current_block_checksumm_data.weak_checksumm);
	}

	index++;
    }

    std::cout<<"Validation executed correctly!"<<endl;
}

bool read_signature_file() {
    string file_path = "/root/fastrdiff/root.hdd.signature";
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

	// Это нормальный код, он просто отключен!
	/*
	printf("weak: %08x offset: %lld ", weak_checksumm, offset);
	printf("md4: ");
	print_md4_summ(md4_checksumm_buffer, md4_truncation_from_file);
	printf("\n");
	*/

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
void hexlify(const char* in, unsigned int size, char* out) {
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

long long unsigned int get_file_size(const char* file_name) {
    struct stat st; 
    stat(file_name, &st);
    
    return st.st_size;
}


// Copy & Paste from: https://github.com/librsync/librsync/blob/master/checksum.c
// GNU LGPL v2.1 

/* We should make this something other than zero to improve the
 * checksum algorithm: tridge suggests a prime number. */
#define RS_CHAR_OFFSET 31

/*
 * A simple 32 bit checksum that can be updated from either end
 * (inspired by Mark Adler's Adler-32 checksum)
 */
unsigned int rs_calc_weak_sum(void const *p, int len) {
    int i;
    unsigned        s1, s2;
    unsigned char const    *buf = (unsigned char const *) p;

    s1 = s2 = 0;
    for (i = 0; i < (len - 4); i += 4) {
	s2 += 4 * (s1 + buf[i]) + 3 * buf[i + 1] + 2 * buf[i + 2] + buf[i + 3] + 10 * RS_CHAR_OFFSET;
	s1 += (buf[i + 0] + buf[i + 1] + buf[i + 2] + buf[i + 3] + 4 * RS_CHAR_OFFSET);
    }

    for (; i < len; i++) {
	s1 += (buf[i] + RS_CHAR_OFFSET);
        s2 += s1;
    }
    
    return (s1 & 0xffff) + (s2 << 16);
}
