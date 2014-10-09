#include <iostream>
#include <vector>

#include <stdint.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>

#include <openssl/md4.h>

using namespace std;

int32_t RS_SIG_MAGIC = 0x72730136;

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

/* Prototypes */
bool generate_signature(string input_file_path, string signature_path);
bool file_exists(string file_path);
int write_int_bigendian(int file_handle, int32_t integer_value);
int strong_md4_checksumm(void const *p, int len, void* md4_digest);
void validate_file(string file_path, string signature_path);
unsigned int rs_calc_weak_sum(void const *p, int len);
long long unsigned int get_file_size(const char* file_name);
void hexlify(const char* in, unsigned int size, char* out);
void print_md4_summ(char* weak_checksumm, int md4_truncation_length);
int read_int(int file_handle, int32_t* int_ptr);
bool read_signature_file(string signature_file, vector<signature_element>& signatures_vector);

int main(int argc, char *argv[]) {
    if (argc < 2) {
	printf("Please specify opertion type: signature, delta or patch");
	exit (1);
    }

    if (strcmp(argv[1], "signature") == 0) {
        if (argc < 4) { 
            printf("Please specify source file and path to signature file\n");
            exit(1);
        }

	generate_signature(argv[2], argv[3]);
    } else if (strcmp(argv[1], "validate") == 0) {
        if (argc < 4) {
            printf("Please specify source file and path to signature file\n");
            exit(1);
        }

	validate_file(argv[2], argv[3]);
    } else if (strcmp(argv[1], "delta") == 0) {
        printf("Delta generation is not realized yet");
        exit(1);
    } else if (strcmp(argv[1], "patch") == 0) {
	printf("patching is not realized yet");
	exit(1);
    } else {
	printf("Not supported operation: %s\n", argv[1]);
	exit(1);
    }

    return 0;
}

/* Generate signature for specified file */
bool generate_signature(string input_file_path, string signature_path) {
    time_t start_time = time(NULL);
    int input_file_handle = open(input_file_path.c_str(), O_RDONLY);

    if (input_file_handle <= 0) {
	std::cout<<"Can't open input file"<<endl;
	return false;
    }

    unsigned long long file_size = get_file_size(input_file_path.c_str());

    if (file_exists(signature_path)) {
	std::cout<<"Signature file already exists, please remove it or change name"<<endl;
	return false;
    }

    int signature_file_handle = open(signature_path.c_str(), O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);

    if (signature_file_handle <= 0) {
	std::cout<<"Can't open signature file wor writing"<<endl;
	return false;
    }

    /* write SIGNATURE header */
    uint32_t block_size = 1024 * 1024;
    uint32_t md4_truncation = 8;

    if (!write_int_bigendian(signature_file_handle, RS_SIG_MAGIC)) {
	std::cout<<"Can't write signature header to signature file"<<endl;
	return false;
    }

    if (!write_int_bigendian(signature_file_handle, block_size)) {
	std::cout<<"Can't write block size to signature file"<<endl;
	return false;
    }	
    
    if (!write_int_bigendian(signature_file_handle, md4_truncation)) {
	std::cout<<"Can't write md4 truncation to signature file"<<endl;
	return false;
    }

    void* buffer = malloc(block_size);
    char md4_checksumm_buffer[8];

    while (true) {
        int readed_bytes = read(input_file_handle, buffer, block_size);

        if (readed_bytes <= 0) {
            break;
        }

	unsigned int weak_checksumm = rs_calc_weak_sum(buffer, readed_bytes);
  
	if (!write_int_bigendian(signature_file_handle, weak_checksumm)) {
	    std::cout<<"Can't write weak checksumm to file"<<endl;
	    return false;
	}
 
	if (!strong_md4_checksumm(buffer, readed_bytes, (void*)md4_checksumm_buffer)) {
	    std::cout<<"Can't generate md4 checksumm"<<endl;
	    return false;
	}

	if (write(signature_file_handle, md4_checksumm_buffer, md4_truncation) != 8) {
	    std::cout<<"Can't write md4 checksumm to signature file"<<endl;
	    return false;
	}
    } 

    fsync(signature_file_handle);

    free(buffer);

    close(input_file_handle);
    close(signature_file_handle); 

    time_t finish_time = time(NULL);
    int total_time = finish_time - start_time;

    if (total_time > 0) {
        printf("Total time consumed by signature generation is: %d seconds generation speed: %.1f MB/s\n", total_time, (float)file_size / total_time / 1024 / 1024);
    }
}

bool file_exists(string file_path) {
    struct stat st;
    int result = stat(file_path.c_str(), &st);
    
    if (result == 0) {
	return true;
    } else {
	return false;
    }
}

void validate_file(string file_path, string signature_path) {
    vector<signature_element> signatures_vector;

    read_signature_file(signature_path, signatures_vector);

    int file_handle = open(file_path.c_str(), O_RDONLY);

    if (file_handle <= 0) {
        std::cout<<"Can't open signature file"<<endl;
        return;   
    }

    unsigned int block_size = 1048576; 

    void* buffer = malloc(block_size);
    unsigned long long int index = 0;
    char md4_checksumm_buffer[8];
    while (true) {
	int readed_bytes = read(file_handle, buffer, block_size);

	if (readed_bytes <= 0) {
	    break;
	}

	unsigned int weak_checksumm = rs_calc_weak_sum(buffer, readed_bytes);
	signature_element current_block_checksumm_data = signatures_vector[index];

	if (current_block_checksumm_data.weak_checksumm == weak_checksumm) {
	    //std::cout<<"Signature match"<<endl;
	    if (!strong_md4_checksumm(buffer, readed_bytes, (void*)md4_checksumm_buffer)) {
		std::cout<<"Can't calculate md4 cheksumm"<<endl;
		break;
	    }

	    if (!strncmp(md4_checksumm_buffer, current_block_checksumm_data.md4_checksumm, 8)) {
		// hashes are equal!
	    } else {
		printf("Hashes mismatch! ");
		print_md4_summ(md4_checksumm_buffer, 8);
		printf(" is not equal to ");
		print_md4_summ(current_block_checksumm_data.md4_checksumm, 8);
		printf("\n");
		break;
	    }
	} else {
	    printf("Signature not matched! File weak summ: %08x signature file weak summ: %08x",
		weak_checksumm, current_block_checksumm_data.weak_checksumm);
	}

	index++;
    }

    std::cout<<"Validation executed correctly with weak and strong checksumms!"<<endl;
}

bool read_signature_file(string file_path, vector<signature_element>& signatures_vector) {
    int file_handle = open(file_path.c_str(), O_RDONLY);

    if (file_handle <= 0) {
	std::cout<<"Can't open signature file"<<endl;
	return false;	
    } 

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

int write_int_bigendian(int file_handle, int32_t integer_value) {
    uint32_t encoded_integer = htobe32(integer_value);

    int bytes_written = write(file_handle, &encoded_integer, sizeof(int32_t));

    // так как может случиться так, что мы записали меньше байт, чем пытались
    if (bytes_written == sizeof(int32_t)) {
	return true;
    } else {
	return false;
    }
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

int strong_md4_checksumm(void const *p, int len, void* md4_digest) {
    MD4_CTX md4_context;

    if (!MD4_Init(&md4_context)) {
	return 0;
    }

    if (!MD4_Update(&md4_context, p, len)) {
	return 0;
    }
    
    if (!MD4_Final((unsigned char*)md4_digest, &md4_context)) {
	return 0;
    }

    return 1;
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
