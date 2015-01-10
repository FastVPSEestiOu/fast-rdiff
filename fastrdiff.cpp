#include <iostream>
#include <fstream>  
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
#include <openssl/md5.h>

// log4cpp logging facility
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

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

/* Structure which describe signature file */
typedef std::map<std::string, unsigned long long> signatures_map_t;
typedef std::vector<signature_element> signatures_vector_t;

typedef struct signature_file_t {
    signatures_map_t    signatures_map;
    uint32_t            block_size;
    uint32_t            hash_truncation;
    uint32_t            hash_type; 
} signature_file_t;

/* Prototypes */

/* High level functions */
bool generate_delta(std::string signature_path, std::string file_path, std::string delta_path);
bool generate_signature(std::string input_file_path, std::string signature_path, uint32_t block_size);
bool read_signature_file(std::string signature_file, signature_file_t& signature_struct);
//void validate_file(string file_path, string signature_path);

/* Data conversion functions */
int read_int(int file_handle, int32_t* int_ptr);
int write_int_bigendian(int file_handle, int32_t integer_value);
int write_64_int_bigendian(int file_handle, long long int integer_value);
std::string stringify_md4_checksumm(unsigned char* md4_checksumm, int md4_truncation_length);
void hexlify(const char* in, unsigned int size, char* out);

/* Wrapper function for transparent md5 calculation for delta file */
ssize_t write_wrapper(int fd, const void *buf, size_t count);

/* Checksumm functions*/
unsigned int rs_calc_weak_sum(void const *p, int len);
int strong_md4_checksumm(void const *p, int len, unsigned char* md4_digest, unsigned int truncate_length);

/* Other functions */
int int_log2(int index);
int rs_int_len(long long int val);
bool file_exists(std::string file_path);
long long unsigned int get_file_size(const char* file_name);

bool we_print_to_stdout = true;
std::string log_file_path = "/tmp/fastrdiff.log";
log4cpp::Category& logger = log4cpp::Category::getRoot();

/* Wrap write function for simple handling all output data */
ssize_t write_wrapper(int fd, const void *buf, size_t count) {
    return write(fd, buf, count);
}

void init_logging() {
    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout(); 
    layout->setConversionPattern ("%d [%p] %m%n"); 

    log4cpp::Appender *appender = new log4cpp::FileAppender("default", log_file_path);
    appender->setLayout(layout);

    logger.setPriority(log4cpp::Priority::INFO);
    logger.addAppender(appender);
    logger.info("Logger initialized!");
}

int main(int argc, char *argv[]) {
    uint32_t block_size = 1024 * 1024;

    init_logging();

    if (argc < 2) {
	logger<<log4cpp::Priority::INFO<<("Please specify opertion type: signature, delta or patch\n");

        return 1;
    }

    if (strcmp(argv[1], "signature") == 0) {
        if (argc < 4) { 
            logger<<log4cpp::Priority::INFO<<("Please specify source file and path to signature file\n");
            return 1;
        }

	if (generate_signature(argv[2], argv[3], block_size) ) {
            return 0;
        } else {
            return 1;
        }
    } else if (strcmp(argv[1], "validate") == 0) {
        if (argc < 4) {
            logger<<log4cpp::Priority::INFO<<("Please specify source file and path to signature file\n");
            return 1;
        }

	//validate_file(argv[2], argv[3]);
    } else if (strcmp(argv[1], "delta") == 0) {
        if (argc < 4) {
            logger<<log4cpp::Priority::INFO<<("Please specify: signature file, new file and delta file paths\n");
            return 1;
        }

        if (generate_delta(argv[2], argv[3], argv[4])) {
            return 0;
        } else {
            return 1;
        }

    } else if (strcmp(argv[1], "patch") == 0) {
	logger<<log4cpp::Priority::INFO<<("patching is not realized yet");
	return 1;
    } else {
	logger<<log4cpp::Priority::INFO<<"Not supported operation: "<<argv[1];
	return 1;
    }

    return 0;
}

/* Generate signature for specified file */
bool generate_signature(std::string input_file_path, std::string signature_path, uint32_t block_size) {
    time_t start_time = time(NULL);
    int input_file_handle = open(input_file_path.c_str(), O_RDONLY);

    if (input_file_handle <= 0) {
	logger<<log4cpp::Priority::INFO<<("Can't open input file\n");
	return false;
    }

    unsigned long long file_size = get_file_size(input_file_path.c_str());

    if (file_exists(signature_path)) {
	logger<<log4cpp::Priority::INFO<<("Signature file already exists, please remove it or change name\n");
	return false;
    }

    int signature_file_handle = open(signature_path.c_str(), O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);

    if (signature_file_handle <= 0) {
	logger<<log4cpp::Priority::INFO<<("Can't open signature file wor writing");
	return false;
    }

    /* write SIGNATURE header */
    uint32_t md4_truncation = 8;

    if (!write_int_bigendian(signature_file_handle, RS_SIG_MAGIC)) {
	logger<<log4cpp::Priority::INFO<<("Can't write signature header to signature file");
	return false;
    }

    if (!write_int_bigendian(signature_file_handle, block_size)) {
	logger<<log4cpp::Priority::INFO<<("Can't write block size to signature file");
	return false;
    }	
    
    if (!write_int_bigendian(signature_file_handle, md4_truncation)) {
	logger<<log4cpp::Priority::INFO<<("Can't write md4 truncation to signature file\n");
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
	    logger<<log4cpp::Priority::INFO<<("Can't write weak checksumm to file\n");
	    return false;
	}
 
	if (!strong_md4_checksumm(buffer, readed_bytes, md4_checksumm_buffer, md4_truncation)) {
	    logger<<log4cpp::Priority::INFO<<("Can't generate md4 checksumm\n");
	    return false;
	}

	if (write_wrapper(signature_file_handle, md4_checksumm_buffer, md4_truncation) != 8) {
	    logger<<log4cpp::Priority::INFO<<("Can't write md4 checksumm to signature file");
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
        char buffer[256];
    
        sprintf(buffer, "Total time consumed by signature generation is: %d seconds generation speed: %.1f MB/s\n", total_time, (float)file_size / total_time / 1024 / 1024);
        logger<<log4cpp::Priority::INFO<<(buffer);
    }

    return true;
}

bool file_exists(std::string file_path) {
    struct stat st;
    int result = stat(file_path.c_str(), &st);
    
    if (result == 0) {
	return true;
    } else {
	return false;
    }
}

bool generate_delta(std::string signature_path, std::string file_path, std::string delta_path) {
    signature_file_t signature_data;

    int file_handle = open(file_path.c_str(), O_RDONLY);

    time_t start_time = time(NULL);
    unsigned long long file_size = get_file_size(file_path.c_str());

    if (file_handle <= 0) {
        logger<<log4cpp::Priority::INFO<<("Can't open signature file\n");
        return false;
    }

    bool we_use_stdout_as_delta_output = false;

    // We use pseudo file name "-" as "stdout"
    if (delta_path.compare("-") == 0 or delta_path.compare("/dev/stdout") == 0) {
        // Replace fake file name by real
        delta_path = "/dev/stdout";
        we_use_stdout_as_delta_output = true;
            
        // Switch log output to log instead stdout
        we_print_to_stdout = false;
    }

    if (we_use_stdout_as_delta_output) {
        // We do not check existence of stdout file
    } else {
        if (file_exists(delta_path)) {
            logger<<log4cpp::Priority::INFO<<("Delta file already exists, please check it\n");
            return false;
        }   
    }

    unsigned long long current_file_size = get_file_size(file_path.c_str());

    if (current_file_size % 1024*1024 != 0) {
        logger<<log4cpp::Priority::INFO<<("We support only files multiples 1MB blocks\n");

        return false;
    }

    if (!read_signature_file(signature_path, signature_data)) {
        logger<<log4cpp::Priority::INFO<<("Can't read signature file! Stop!");
        return false;
    }

    int delta_file_handle = open(delta_path.c_str(), O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
    
    if (delta_file_handle <= 0) {
        logger<<log4cpp::Priority::INFO<<("Can't open delta file for writing");
        return false;
    }

    // Таким образом мы можем узнать примерный размер старого файла 
    unsigned long long old_file_size = 1024 * 1024 * signature_data.signatures_map.size();

    if (current_file_size == old_file_size) {
        logger<<log4cpp::Priority::INFO<<("File size is not changed");
    } else if (current_file_size > old_file_size) {
        logger<<log4cpp::Priority::INFO<<("New file has increased size");
    } else {
        logger<<log4cpp::Priority::INFO<<("New file was shrinked");
    }

    unsigned int block_size = signature_data.block_size;  
    void* buffer = malloc(block_size);
    unsigned long long int current_offset = 0; 
    unsigned char md4_checksumm_buffer[8];

    // Add DELTA signature
    write_int_bigendian(delta_file_handle, RS_DELTA_MAGIC);

    // For calculation MD5 for whole file
    static unsigned char md5_16byte_buffer[16];
    MD5_CTX md5_context_whole_source_file;

    // For calculation MD5 of delta file
    static unsigned char md5_16byte_buffer_delta_signature[16];
    MD5_CTX md5_context_delta_file;

    if (!MD5_Init(&md5_context_whole_source_file)) {
        logger<<log4cpp::Priority::INFO<<"Can't init md5 context for whole file";
        return false;
    }

    if (!MD5_Init(&md5_context_delta_file)) {
        logger<<log4cpp::Priority::INFO<<"Can't init md5 context for delta file";
        return false;
    }


    while (true) {
        int readed_bytes = read(file_handle, buffer, block_size);

        if (readed_bytes <= 0) {
            break;
        }

        if (!strong_md4_checksumm(buffer, readed_bytes, md4_checksumm_buffer, 8)) {
            logger<<log4cpp::Priority::INFO<<("Can't calculate md4 cheksumm");
            return false;
        }

        if (!MD5_Update(&md5_context_whole_source_file, buffer, readed_bytes)) {
            logger<<log4cpp::Priority::INFO<<"Can't update md5 checksumm for whole file";
            return false;
        }

        // construct key
        std::string md4_as_string = stringify_md4_checksumm(md4_checksumm_buffer, 8);

        // try to find it in signature
        //print_md4_summ(md4_as_string, 8);
        signatures_map_t::iterator it = signature_data.signatures_map.find(md4_as_string);
        if (it == signature_data.signatures_map.end()) {
            // We do not found any blocks in signature for this checksumm
            // Initiate literal generation
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
            if (write_wrapper(delta_file_handle, &command, 1) != 1) {
                logger<<log4cpp::Priority::INFO<<("Can't write command to file");
                return false;
            }

            // В общем случае так делать нельзя, но у нас известно, что блоки по 1 миллиону байт
            // и этот размер у нас всегда 4х байтовый
            if (!write_int_bigendian(delta_file_handle, literal_len)) {
                logger<<log4cpp::Priority::INFO<<("Can't write literal len");
                return false;
            }

            if (write_wrapper(delta_file_handle, buffer, block_size) != block_size) {
                logger<<log4cpp::Priority::INFO<<("Can't write literal to delta file");
                return false;
            }
        } else {
            // We found data in source file by signature
            unsigned long long int md4_offset = it->second;
            // std::cout<<"Match: copy, offset: "<<md4_offset<<endl;

            if (md4_offset == current_offset) {
                //std::cout<<"In place"<<endl; 
            } else {
                //std::cout<<"Data shift"<<endl;
            }

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
 
            if (write_wrapper(delta_file_handle, &command, 1) != 1) {
                logger<<log4cpp::Priority::INFO<<("Can't write command to file");
                return false;
            }

            if (!write_64_int_bigendian(delta_file_handle, md4_offset)) {
                logger<<log4cpp::Priority::INFO<<("Can't write offset");
                return false;
            }
    
            // В общем случае так делать нельзя, но у нас известно, что блоки по 1 миллиону байт
            // и этот размер у нас всегда 4х байтовый
            if (!write_int_bigendian(delta_file_handle, block_size)) {
                logger<<log4cpp::Priority::INFO<<("Can't write copy len");
                return false;
            }
        }

        current_offset += block_size; 
    }

    // Finish md5 calculation for whole file 
    if (!MD5_Final(md5_16byte_buffer, &md5_context_whole_source_file)) {
        logger<<log4cpp::Priority::INFO<<("Can't finish md5 calculation");
        return false;
    }

    std::string md5_whole_file_as_string = stringify_md4_checksumm(md5_16byte_buffer, 16);

    // Write finish byte!
    uint32_t zero_integer = 0;
    if (write_wrapper(delta_file_handle, &zero_integer, 1) != 1) {
        logger<<log4cpp::Priority::INFO<<("Can't wrote finish byte");
        return false;
    }

    // Print whole file checksumm into file
    std::string md5_whole_file_file_name = delta_path + ".md5";
    std::ofstream md5_out_file(md5_whole_file_file_name.c_str());
    md5_out_file<<md5_whole_file_as_string<<"\n";
    md5_out_file.close();

    time_t finish_time = time(NULL);
    int total_time = finish_time - start_time;

    if (total_time > 0) {
        char buffer[256];

        sprintf(buffer, "Total time consumed by delta generation is: %d seconds generation speed: %.1f MB/s\n", total_time, (float)file_size / total_time / 1024 / 1024);
        logger<<log4cpp::Priority::INFO<<(buffer);
    } 

    return true;
}

// TODO: валидатор кривой, не сверяет размер толком, в случае если файл удлиннился ничего не сработает нормально
/*
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
		std::cout<<stringify_md4_checksumm(md4_checksumm_buffer, 8);
		printf(" is not equal to ");
		std::cout<<stringify_md4_checksumm(current_block_checksumm_data.md4_checksumm, 8);
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
*/

// Read signature file to in memory structure
bool read_signature_file(std::string file_path, signature_file_t& signature_struct) {
    unsigned long long file_size = get_file_size(file_path.c_str());
    
    int32_t file_signature_from_file = 0;
    int32_t blocksize_from_file = 0;
    int32_t md4_truncation_from_file = 0;

    int file_handle = open(file_path.c_str(), O_RDONLY);

    if (file_handle <= 0) {
	logger<<log4cpp::Priority::INFO<<("Can't open signature file");
	return false;	
    } 

    if (!read_int(file_handle, &file_signature_from_file)) {
        logger<<log4cpp::Priority::INFO<<("Can't read file signature");
        return false;
    }

    if (file_signature_from_file != RS_SIG_MAGIC) {
	logger<<log4cpp::Priority::INFO<<("Can't find signature magic number");
	return false;
    }

    if (!read_int(file_handle, &blocksize_from_file)) {
        logger<<log4cpp::Priority::INFO<<("Can't read block size from file");
        return false;
    }

    if (blocksize_from_file > 0 && blocksize_from_file % 2 == 0) {
	logger<<log4cpp::Priority::INFO<<"We read block size:"<<blocksize_from_file;
    } else {
	logger<<log4cpp::Priority::INFO<<"Block size readed from signature is broken because it's null or it's not an pow of 2: "<<blocksize_from_file;

	return false;
    }

    if (!read_int(file_handle, &md4_truncation_from_file)) {
        logger<<log4cpp::Priority::INFO<<("Can't read md4 truncation from file");
        return false;
    }

    if (md4_truncation_from_file < 1 or md4_truncation_from_file > 16) {
	logger<<log4cpp::Priority::INFO<<"Truncation is: "<<md4_truncation_from_file;
	return false;
    }

    if (md4_truncation_from_file != 8) {
	logger<<log4cpp::Priority::INFO<<("We support only 8 byte md4 truncation! Sorry :(");
	return false;
    }

    logger<<log4cpp::Priority::INFO<<"Truncation for md4 is: "<<md4_truncation_from_file;
 
    signature_struct.hash_type = 0x7777; /* md4 */
    signature_struct.hash_truncation = md4_truncation_from_file;
    signature_struct.block_size = blocksize_from_file;
 
    // TODO: пока не ясно как сделать поддержку динамического размера, но я не думаю, что она вообще кому-то нужна
    unsigned char md4_checksumm_buffer[8];

    // Размер одной записи примерно
    // Вычетаем размер хидера и делим на размер одной сигнатуры 
    unsigned long long signatures_count = int ( (file_size - sizeof(uint32_t) * 3) / (sizeof(uint32_t) + md4_truncation_from_file));

    logger<<log4cpp::Priority::INFO<<"We calculated approximate signatures number as: "<<signatures_count;

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
	std::cout<<stringify_md4_checksumm(md4_checksumm_buffer, md4_truncation_from_file);
	printf("\n");
	*/

        std::string md4_as_string = stringify_md4_checksumm(md4_checksumm_buffer, md4_truncation_from_file);
        signature_struct.signatures_map[ md4_as_string ] = offset;

	offset += blocksize_from_file; 
    }

    return true;
}

std::string stringify_md4_checksumm(unsigned char* md4_checksumm, int md4_truncation_length) {
    // THIS CAN KILL APPLICAION BECAUSE THIS CODE IS NOT THREAD SAFE
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

    int bytes_written = write_wrapper(file_handle, &encoded_integer, sizeof(int32_t));

    // так как может случиться так, что мы записали меньше байт, чем пытались
    if (bytes_written == sizeof(int32_t)) {
	return true;
    } else {
	return false;
    }
}

int write_64_int_bigendian(int file_handle, long long int integer_value) {
    long long int encoded_integer = htobe64(integer_value);

    int bytes_written = write_wrapper(file_handle, &encoded_integer, sizeof(long long int));
    
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


// Function from librsync, checksum.c
// GNU LGPL v2.1 

// We should make this something other than zero to improve the
// checksum algorithm: tridge suggests a prime number.
#define RS_CHAR_OFFSET 31

// A simple 32 bit checksum that can be updated from either end
// (inspired by Mark Adler's Adler-32 checksum)
unsigned int rs_calc_weak_sum(void const *p, int len) {
    int i;
    unsigned        s1, s2;
    unsigned char const *buf = (unsigned char const *) p;

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
        logger<<log4cpp::Priority::INFO<<("Can't encode integer");
        exit(1);
    }
}

// Integer logarithm for 2 
// TODO: it's potential performance killer due to float arithmetics
int int_log2(int index) {
    return int(log(index)/log(2));
}
