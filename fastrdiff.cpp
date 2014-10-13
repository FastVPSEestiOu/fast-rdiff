#include <iostream>
#include <vector>
#include <map>
#include <utility>

#include <stdint.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/md4.h>

using namespace std;

/* rdiff signatures */
int32_t RS_SIG_MAGIC = 0x72730136;
int32_t RS_DELTA_MAGIC = 0x72730236;

/*

1. Добавить в будущем поддержку файлов не кратных мегабайту
2. Добавить возможность отправки дельты на stdout
3. Хэшировать файл целиком и сохранять его сигнатуру хотя бы в лог
4. Добавить патчер
5. Добавить тесты (мб от librsync? Хорошая идея: make all check)
6. Добавить парсер аргументов командной строки
7. Сделаеть указываемый извне blocksize

*/

typedef struct signature_element {
    unsigned char md4_checksumm[8];
    int32_t weak_checksumm;
    unsigned long long offset;
} signature_element;

typedef std::map<std::string, unsigned long long> signatures_map_t;
typedef vector<signature_element> signatures_vector_t;

/* Prototypes */
int int_log2(int index);
string stringify_md4_checksumm(unsigned char* md4_checksumm, int md4_truncation_length);
int rs_int_len(long long int val);
bool generate_delta(string signature_path, string file_path, string delta_path);
bool generate_signature(string input_file_path, string signature_path);
bool file_exists(string file_path);
int write_int_bigendian(int file_handle, int32_t integer_value);
int write_64_int_bigendian(int file_handle, long long int integer_value);
int strong_md4_checksumm(void const *p, int len, unsigned char* md4_digest, unsigned int truncate_length);
void validate_file(string file_path, string signature_path);
unsigned int rs_calc_weak_sum(void const *p, int len);
long long unsigned int get_file_size(const char* file_name);
void hexlify(const char* in, unsigned int size, char* out);
void print_md4_summ(unsigned char* weak_checksumm, int md4_truncation_length);
int read_int(int file_handle, int32_t* int_ptr);
bool read_signature_file(string signature_file, vector<signature_element>& signatures_vector);

int main(int argc, char *argv[]) {
    if (argc < 2) {
	printf("Please specify opertion type: signature, delta or patch\n");
	exit (1);
    }

    if (strcmp(argv[1], "signature") == 0) {
        if (argc < 4) { 
            printf("Please specify source file and path to signature file\n");
            exit(1);
        }

	if (generate_signature(argv[2], argv[3])) {
            return 0;
        } else {
            return 1;
        }
    } else if (strcmp(argv[1], "validate") == 0) {
        if (argc < 4) {
            printf("Please specify source file and path to signature file\n");
            exit(1);
        }

	validate_file(argv[2], argv[3]);
    } else if (strcmp(argv[1], "delta") == 0) {
        if (argc < 4) {
            printf("Please specify: signature file, new file and delta file paths\n");
            exit(1);
        }

        if (generate_delta(argv[2], argv[3], argv[4])) {
            exit(0);
        } else {
            exit(1);
        }

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
    unsigned char md4_checksumm_buffer[8];

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
 
	if (!strong_md4_checksumm(buffer, readed_bytes, md4_checksumm_buffer, md4_truncation)) {
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

    return true;
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

bool generate_delta(string signature_path, string file_path, string delta_path) {
    int file_handle = open(file_path.c_str(), O_RDONLY);

    time_t start_time = time(NULL);
    unsigned long long file_size = get_file_size(file_path.c_str());

    if (file_handle <= 0) {
        std::cout<<"Can't open signature file"<<endl;
        return false;
    }

    if (file_exists(delta_path)) {
        std::cout<<"Delta file already exists, please check it"<<endl;
        return false;
    }   

    unsigned long long current_file_size = get_file_size(file_path.c_str());

    if (current_file_size % 1024*1024 != 0) {
        std::cout<<"We support only files multiples 1MB blocks"<<std::endl;
        return false;
    }

    signatures_vector_t signatures_vector;
    if (!read_signature_file(signature_path, signatures_vector)) {
        std::cout<<"Can't read signature file! Stop!"<<endl;
        return false;
    }

    signatures_map_t signatures_map;

    // TODO: add to map without vector
    for (signatures_vector_t::iterator ii = signatures_vector.begin(); ii != signatures_vector.end(); ++ii) {
        string md4_as_string = stringify_md4_checksumm(ii->md4_checksumm, 8);

        signatures_map[ md4_as_string ] = ii->offset;
    } 

    int delta_file_handle = open(delta_path.c_str(), O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
    
    if (delta_file_handle <= 0) {
        std::cout<<"Can't open delta file for writing"<<endl;
        return false;
    }

    // Таким образом мы можем узнать точный размер старого файла 
    unsigned long long old_file_size = 1024 * 1024 * signatures_vector.size();

    if (current_file_size == old_file_size) {
        cout<<"File size is not changed"<<endl;
    } else if (current_file_size > old_file_size) {
        cout<<"New file has increased size"<<endl;
    } else {
        cout<<"New file was shrinked"<<endl;
    }

    // clean up vector
    signatures_vector.clear();

    unsigned int block_size = 1048576;  
    void* buffer = malloc(block_size);
    unsigned long long int current_offset = 0; 
    unsigned char md4_checksumm_buffer[8];

    // Add DELTA signature
    write_int_bigendian(delta_file_handle, RS_DELTA_MAGIC);
 
    while (true) {
        int readed_bytes = read(file_handle, buffer, block_size);

        if (readed_bytes <= 0) {
            // Write end of file!!!
            break;
        }

        if (!strong_md4_checksumm(buffer, readed_bytes, md4_checksumm_buffer, 8)) {
            std::cout<<"Can't calculate md4 cheksumm"<<endl;
            break;
        }

        // construct key
        string md4_as_string = stringify_md4_checksumm(md4_checksumm_buffer, 8);

        // try to find it in signature
        //print_md4_summ(md4_as_string, 8);
        signatures_map_t::iterator it = signatures_map.find(md4_as_string);
        if (it == signatures_map.end()) {
            // not found
            // INITIATE LITERAL
            // std::cout<<"Not match: new literal"<<endl;
            // в коде librsync: rs_emit_literal_cmd
            /*
                literal_len = len(self.data)
                literal_len_length = byte_length(literal_len)
                command = 0x41 + log2(literal_len_length)
                return command.to_bytes(1, 'big') + literal_len.to_bytes(literal_len_length, 'big') + self.data
            */
            
            // Размер литерала у нас не меняется
            int literal_len = block_size;
            int literal_len_len = rs_int_len(literal_len);
            // в общем-то этот параметр тоже можно зафиксировать и не дергать функцию
            // int32_t literal_len_len = 4;

            // Тут у нас получается: 0x41 + 2 = 0x43
            int32_t command = 0x41 + int_log2(literal_len_len);

            //printf("literal command: %x\n", command);

            // Тут у therealmik странность, зачем 1 байт преобразовыввать в big endian? Он же не изменится :)
            // Учитывая, что у нас little endian, то все значащие данные у нас в самом начале 4х байтового целого
            // проверил этот подход на тест стенде, все ок!
            if (write(delta_file_handle, &command, 1) != 1) {
                std::cout<<"Can't write command to file"<<endl;
                return false;
            }

            // В общем случае так делать нельзя, но у нас известно, что блоки по 1 миллиону байт
            // и этот размер у нас всегда 4х байтовый
            if (!write_int_bigendian(delta_file_handle, literal_len)) {
                std::cout<<"Can't write literal len"<<endl;
                return false;
            }

            if (write(delta_file_handle, buffer, block_size) != block_size) {
                std::cout<<"Can't write literal to delta file"<<endl;
                return false;
            }
        } else {
            // found
            unsigned long long int md4_offset = it->second;
            // INITIALE COPY
            // std::cout<<"Match: copy, offset: "<<md4_offset<<endl;

            if (md4_offset == current_offset) {
                //std::cout<<"In place"<<endl; 
            } else {
                //std::cout<<"Data shift"<<endl;
            }

            // в коде librsync: rs_emit_copy_cmd
            /*  
                offset_len = byte_length(self.offset)
                length_len = byte_length(self.length)
                command = 0x45 + ( log2(offset_len) * 4 ) + log2(length_len)
                return command.to_bytes(1, 'big') + self.offset.to_bytes(offset_len, 'big') + self.length.to_bytes(length_len, 'big')
            */ 

            //int offset_length = rs_int_len(md4_offset);
            int offset_length = 8; // Упростим код и будем рассматривать все смещения как 8 байтовые и всего делов
            int length_length = rs_int_len(block_size);

            // Тут у нас получается: 0x45 + 3 * 4 + 2 = 0x53 
            int32_t command = 0x45 + int_log2(offset_length) * 4 + int_log2(length_length);
           
            //printf("copy command: %x\n", command);
 
            if (write(delta_file_handle, &command, 1) != 1) {
                std::cout<<"Can't write command to file"<<endl;
                return false;
            }

            if (!write_64_int_bigendian(delta_file_handle, md4_offset)) {
                std::cout<<"Can't write offset"<<endl;
                return false;
            }
    
            // В общем случае так делать нельзя, но у нас известно, что блоки по 1 миллиону байт
            // и этот размер у нас всегда 4х байтовый
            if (!write_int_bigendian(delta_file_handle, block_size)) {
                std::cout<<"Can't write copy len"<<endl;
                return false;
            }
        }

        current_offset += block_size; 
    }

    // Write finish byte!
    uint32_t zero_integer = 0;
    if (write(delta_file_handle, &zero_integer, 1) != 1) {
        std::cout<<"Can't wrote finish byte"<<endl;
        return false;
    }

    time_t finish_time = time(NULL);
    int total_time = finish_time - start_time;

    if (total_time > 0) {
        printf("Total time consumed by delta generation is: %d seconds generation speed: %.1f MB/s\n", total_time, (float)file_size / total_time / 1024 / 1024);
    } 

    return true;
}

// TODO: валидатор кривой, не сверяет размер толком, в случае если файл удлиннился ничего не сработает нормально
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
    unsigned char md4_checksumm_buffer[8];

    bool validation_success = true;
    while (true) {
	int readed_bytes = read(file_handle, buffer, block_size);

	if (readed_bytes <= 0) {
	    break;
	}

	unsigned int weak_checksumm = rs_calc_weak_sum(buffer, readed_bytes);
	signature_element current_block_checksumm_data = signatures_vector[index];

	if (current_block_checksumm_data.weak_checksumm == weak_checksumm) {
	    //std::cout<<"Signature match"<<endl;
	    if (!strong_md4_checksumm(buffer, readed_bytes, md4_checksumm_buffer, 8)) {
		std::cout<<"Can't calculate md4 cheksumm"<<endl;
                validation_success = false;
		break;
	    }

	    if (!memcmp(md4_checksumm_buffer, current_block_checksumm_data.md4_checksumm, 8)) {
		// hashes are equal!
	    } else {
		printf("Hashes mismatch at %lld! ", index);
		print_md4_summ(md4_checksumm_buffer, 8);
		printf(" is not equal to ");
		print_md4_summ(current_block_checksumm_data.md4_checksumm, 8);
		printf("\n");
                validation_success = false;
		break;
	    }
	} else {
	    printf("Signature not matched at %lld MB! File weak summ: %08x signature file weak summ: %08x\n",
		index, weak_checksumm, current_block_checksumm_data.weak_checksumm);

            validation_success = false;
            break;
	}

	index++;
    }

    if (validation_success) {
        std::cout<<"Validation executed correctly with weak and strong checksumms!"<<endl;
    }
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
	memcpy(current_element.md4_checksumm, md4_checksumm_buffer, 8);
	current_element.weak_checksumm = weak_checksumm;
	current_element.offset = offset;
	
	signatures_vector.push_back(current_element);
	offset += blocksize_from_file; 
    }

    // rollsum, md4 signature, offset
    return true;
}

void print_md4_summ(unsigned char* md4_checksumm, int md4_truncation_length) {
    char output[32];

    hexlify((char*)md4_checksumm, md4_truncation_length, output);
    printf("%s", output);
}

string stringify_md4_checksumm(unsigned char* md4_checksumm, int md4_truncation_length) {
    // THIS CAN KILL THREADFUL APPICATION!!!
    static char output[32];

    hexlify((char*)md4_checksumm, md4_truncation_length, output);

    return std::string(output);
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

int write_64_int_bigendian(int file_handle, long long int integer_value) {
    long long int encoded_integer = htobe64(integer_value);

    int bytes_written = write(file_handle, &encoded_integer, sizeof(long long int));
    
    if (bytes_written == sizeof(long long int)) {
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

int strong_md4_checksumm(void const *p, int len, unsigned char* md4_digest, unsigned int truncate_length) {
    // THREAD SAFETY IN DANGER!!!
    static unsigned char md4_16byte_buffer[16];

    MD4_CTX md4_context;

    if (!MD4_Init(&md4_context)) {
	return 0;
    }

    if (!MD4_Update(&md4_context, p, len)) {
	return 0;
    }

       
    if (truncate_length == 16) {
        if (!MD4_Final(md4_digest, &md4_context)) {
	    return 0;
        }
    } else {
       // В противном случае нам нужно положить данные в буфер и уже оттуда выдать тому, кто их требует 
        if (!MD4_Final(md4_16byte_buffer, &md4_context)) {
            return 0;
        }

        memcpy(md4_digest, md4_16byte_buffer, truncate_length);
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

// Copy & Paste from: librsync, netint.c
// тип rs_long_t был заменен на long long int
int rs_int_len(long long int val) {
    if (!(val & ~(long long int)0xff)) {
        return 1;
    } else if (!(val & ~(long long int)0xffff)) {
        return 2;
    } else if (!(val & ~(long long int)0xffffffff)) {
        return 4;
    } else if (!(val & ~(long long int)0xffffffffffffffff)) {
        return 8;
    } else {
        std::cout<<"Can't encode integer"<<endl;
        exit(1);
    }
}

// Целочисленный логарифм по основанию 2, потенциальный киллер безопасности,
// так как использует  арифметику с плавающей запятой!
int int_log2(int index) {
    return int(log(index)/log(2));
}
