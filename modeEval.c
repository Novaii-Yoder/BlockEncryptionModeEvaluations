#define _OPENSSL_API_COMPAT 10102
#include <openssl/des.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

const char *keyStr = "A2C4E6G8";
const char *IV = "09876543";
char *fileContents;
char *cipherContents;
char *decryptedContents;
long fileSize;
DES_key_schedule key_schedule;

typedef struct {long start, end; int level;} input;
void DES_ECB_threads_helper(long, long);
void DES_ECB_threads_helper_de(long, long);

// Function to convert a unsinged char array to char array
void binaryToASCII(const unsigned char *input, int length, char *output) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i];
    }
    output[length] = '\0';
} // end of binaryToASCII()

void convertKeyString(DES_cblock *key, const char* keyStr){
	if(strlen(keyStr) != 8){
		printf("ERROR: Key length is not 8\n");
		exit(1);
	}
	unsigned char keyData[8]; 
	for(int i = 0; i < 8; i++){
		sscanf(keyStr + 2 * i, "%shhx", &keyData[i]);
		printf("test\n");
	}
	memcpy(*key, keyData, sizeof(keyData));
} // end of convertKeyString()

// Encryption for DES using ECB mode not using parrallelization
void encryptDES_ECB_serial(){
	
	DES_cblock plaintext, ciphertext;
	for(int tmp = 0; tmp < fileSize; tmp += 8){
		int i;
		for(i = 0; i < 8; i++){
			plaintext[i] = fileContents[i + tmp];
		}
	
		DES_ecb_encrypt(&plaintext, &ciphertext, &key_schedule, DES_ENCRYPT);

		for(i = 0; i < 8; i++){
			cipherContents[tmp + i] = ciphertext[i];
		}
	}
	return;
} // end of encryptDES_ECB_serial


// Decryption for DES using the ECB block mode and no parrallelization
void decryptDES_ECB_serial(){
	
	DES_cblock ciphertext, decrypted_text;
	for(int tmp = 0; tmp < fileSize; tmp += 8){
		int i;
		for(i = 0; i < 8; i++){
			ciphertext[i] = cipherContents[i + tmp];
		}
	
		DES_ecb_encrypt(&ciphertext, &decrypted_text, &key_schedule, DES_DECRYPT);
	
		for(i = 0; i < 8; i++){
			decryptedContents[tmp + i] = decrypted_text[i];
		}
	}
	return;
} // end of decryptDES_ECB_serial

// Encryption for DES using ECB mode using parrallelization
void encryptDES_ECB_threads(input * vs){
	long start = (*vs).start;
	long end = (*vs).end;
	int level = (*vs).level;
	//printf("%d, %d, %d\n", start, end, level);
	DES_cblock plaintext, ciphertext;
	int status;
	pthread_t t_child;
	long mid = (((end - start) / 2) / 8) * 8;
	//printf("%d\n", mid);

	input vals;
	vals.start = mid + 1;
	vals.end = end;
	vals.level = level - 1;

	if(level <= 0 || (end - start) <= 8){
		DES_ECB_threads_helper(start, end);
		return;
	}
	int t;
	if((t = pthread_create(&t_child, NULL, (void *)encryptDES_ECB_threads, &vals)) != 0){
               	printf("ERROR: cannot create thread %d   %d\n", t, level);
               	exit(1);
        }

	//printf("::::%d\n", vals.start );
	
	// parent thread
	input val;
	val.start = 0;
	val.end = mid;
	val.level = level - 1;
	encryptDES_ECB_threads(&val);

	if(pthread_join(t_child, (void**) &status) != 0){
		printf("ERROR: cannot join thread\n");
		exit(1);
	}
	
	return;
} // end of encryptDES_ECB_threads

void DES_ECB_threads_helper(long start, long end){
	int i, j;
	int numBlocks = (end - start) / 8;
	DES_cblock plaintext, ciphertext;
	for(j = 0; j < numBlocks; j++){ 
		for(i = 0; i < 8; i++){
			plaintext[i] = fileContents[i + start +(j * 8)];
		}
	
		DES_ecb_encrypt(&plaintext, &ciphertext, &key_schedule, DES_ENCRYPT);
		
		for(i = 0; i < 8; i++){
			cipherContents[i + start + (j * 8)] = ciphertext[i];
		}
	}
	return;
} // end of DES_ECB_threads_helper()



// Decryption for DES using ECB mode using parrallelization
void decryptDES_ECB_threads(input * vs){
	long start = (*vs).start;
	long end = (*vs).end;
	int level = (*vs).level;
	//printf("%d, %d, %d\n", start, end, level);
	DES_cblock plaintext, ciphertext;
	int status;
	pthread_t t_child;
	long mid = (((end - start) / 2) / 8) * 8;
	//printf("%d\n", mid);

	input vals;
	vals.start = mid + 1;
	vals.end = end;
	vals.level = level - 1;

	if(level <= 0 || (end - start) <= 8){
		DES_ECB_threads_helper_de(start, end);
		return;
	}
	int t;
	if((t = pthread_create(&t_child, NULL, (void *)decryptDES_ECB_threads, &vals)) != 0){
               	printf("ERROR: cannot create thread %d   %d\n", t, level);
               	exit(1);
        }

	//printf("::::%d\n", vals.start );
	
	// parent thread
	input val;
	val.start = 0;
	val.end = mid;
	val.level = level - 1;
	encryptDES_ECB_threads(&val);

	if(pthread_join(t_child, (void**) &status) != 0){
		printf("ERROR: cannot join thread\n");
		exit(1);
	}
	
	return;
} // end of decryptDES_ECB_threads

void DES_ECB_threads_helper_de(long start, long end){
	int i, j;
	int numBlocks = (end - start) / 8;
	DES_cblock ciphertext, deciphertext;
	for(j = 0; j < numBlocks; j++){ 
		for(i = 0; i < 8; i++){
			ciphertext[i] = cipherContents[i + start +(j * 8)];
		}
	
		DES_ecb_encrypt(&ciphertext, &deciphertext, &key_schedule, DES_DECRYPT);
		
		for(i = 0; i < 8; i++){
			decryptedContents[i + start + (j * 8)] = deciphertext[i];
		}
	}
	return;
} // end of DES_ECB_threads_helper_de()



// Encryption for CBC mode
void encrypt_DES_CBC(){
	
	DES_cblock plaintext, ciphertext;
	int i;
	for(i = 0; i < 8; i++){
		plaintext[i] = fileContents[i] ^ IV[i];
	}
	
	DES_ecb_encrypt(&plaintext, &ciphertext, &key_schedule, DES_ENCRYPT);

	for(i = 0; i < 8; i++){
		cipherContents[i] = ciphertext[i];
	}
	
	for(int tmp = 8; tmp < fileSize; tmp += 8){
		for(i = 0; i < 8; i++){
			plaintext[i] = fileContents[i + tmp] ^ ciphertext[i];
		}
	
		DES_ecb_encrypt(&plaintext, &ciphertext, &key_schedule, DES_ENCRYPT);

		for(i = 0; i < 8; i++){
			cipherContents[tmp + i] = ciphertext[i];
		}
	}
	return;
} // end of encrypt_DES_CBC()

// Decryption for CBC mode
void decrypt_DES_CBC(){
	
	DES_cblock decryptedtext, ciphertext;
	int i;
	for(i = 0; i < 8; i++){
		ciphertext[i] = cipherContents[i];
	}
	
	DES_ecb_encrypt(&ciphertext, &decryptedtext, &key_schedule, DES_DECRYPT);

	for(i = 0; i < 8; i++){
		decryptedContents[i] = decryptedtext[i] ^ IV[i];
	}
	
	for(int tmp = 8; tmp < fileSize; tmp += 8){
		for(i = 0; i < 8; i++){
			ciphertext[i] = cipherContents[i + tmp];
		}
	
		DES_ecb_encrypt(&ciphertext, &decryptedtext, &key_schedule, DES_DECRYPT);

		for(i = 0; i < 8; i++){
			decryptedContents[tmp + i] = decryptedtext[i];
		}
	}
	return;
} // end of decrypt_DES_CBC()

#define BLOCK_SIZE 8

typedef struct {
    char *input[8];
    char *output[8];
    int block_count;
} ThreadData;

// CHAT GPT CODE
void *encryptDESBlock(void *data) {
    ThreadData *threadData = (ThreadData *)data;
        DES_ecb_encrypt((DES_cblock *)(threadData->input), (DES_cblock *)(threadData->output), &key_schedule, DES_ENCRYPT);
    pthread_exit(NULL);
}
// CHAT GPT CODE
int enc(){
    FILE *inputFile = fopen("plaintextlong.txt", "rb");
    FILE *outputFile = fopen("output.txt", "wb");

    if (!inputFile || !outputFile) {
        perror("File open error");
        return 1;
    }

    DES_cblock key;
    DES_random_key(&key);
    DES_set_key(&key, &key_schedule);

    fseek(inputFile, 0, SEEK_END);
    long fileSize = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);

    int numThreads = 4; // You can adjust the number of threads as needed
    int blockSize = fileSize / numThreads;

    pthread_t threads[numThreads];
    ThreadData threadData[numThreads];

    for (int i = 0; i < numThreads; i++) {
        for (int j = 0; j < 8; j++) {
            threadData[i].input[j] = malloc(BLOCK_SIZE * sizeof(char));
            threadData[i].output[j] = malloc(BLOCK_SIZE * sizeof(char));
        }
        threadData[i].block_count = blockSize / BLOCK_SIZE;
        fread(threadData[i].input, 1, blockSize, inputFile);
    }

    for (int i = 0; i < numThreads; i++) {
        if (pthread_create(&threads[i], NULL, encryptDESBlock, &threadData[i]) != 0) {
            perror("Thread creation error");
            return 1;
        }
    }

    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < numThreads; i++) {
        for (int j = 0; j < 8; j++) {
            fwrite(threadData[i].output[j], 1, BLOCK_SIZE, outputFile);
            free(threadData[i].input[j]);
            free(threadData[i].output[j]);
        }
    }

    fclose(inputFile);
    fclose(outputFile);
    return 0;
}


int main(void){
	
	//enc();


	DES_cblock key;
	DES_cblock plaintext, ciphertext, decrypted_text;

	if(strlen(keyStr) != 8){
		printf("ERROR: Key length is not 8\n");
		exit(1);
	}
	unsigned char keyData[8]; 
	for(int i = 0; i < 8; i++){
		sscanf(keyStr + 2 * i, "%shhx", &keyData[i]);
	}
	memcpy(key, keyData, sizeof(keyData));
	//convertKeyString(&key, keyStr);
		
	DES_set_key((const_DES_cblock *)key, &key_schedule);
	
	// end of key initialization



	// Open file and get contents	
	FILE *file = fopen("plaintextshrek.txt", "r");
	if(file == NULL){
		printf("ERROR: File not found\n");
		exit(1);
	} // make sure file exists

	fseek(file, 0, SEEK_END);
	fileSize = ftell(file);
	rewind(file);
	
	int tmp;
	int padding = (tmp = (fileSize % 8)) == 0? 0: 8 - tmp;	
	fileContents = (char *)malloc(fileSize + padding + 1);
	if(fileContents == NULL){
		printf("ERROR: Bad malloc, file probably too big\n");
		fclose(file);
		exit(1);
	} // check for malloc error
	
	size_t bytesRead = fread(fileContents, 1, fileSize, file);
	if(bytesRead != fileSize){
		printf("ERROR: reading file\n");
		free(fileContents);
		fclose(file);
		exit(1);
	} // check to see if all data was read

	for(long i = fileSize; i <= fileSize + padding; i++){
		fileContents[i] = '\0';
	} // pad the fileContents with null terminators	
	fileSize += padding;
	
	fclose(file); // close the file, we are done with it

	
	cipherContents = (char *)malloc(fileSize + 1);
	decryptedContents = (char *)malloc(fileSize + 1);
	if(cipherContents == NULL || decryptedContents == NULL){
		printf("ERROR: bad malloc\n");
		exit(1);
	} // check for bad malloc
	
	struct timespec s_starttimer, s_endtimer;






//************************************** ECB Serial ***********************************
	// Run the encryption once before timers
	// I was get weird times when just jumping into the timers
	// the first encryption operation was taking way longer than it should have
	encryptDES_ECB_serial(key_schedule);
	decryptDES_ECB_serial(key_schedule);


	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime
	
	encryptDES_ECB_serial();
	
	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	int i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	int j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_encrypt_DES_ECB_serial = i * 1000000000 + j;
	
	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime

	decryptDES_ECB_serial();
	
	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_decrypt_DES_ECB_serial = i * 1000000000 + j;

	printf("ECB Thread********************************************\n");
	printf("Encryption: %d nanoseconds\n", time_encrypt_DES_ECB_serial);
	printf("Decyrption: %d nanoseconds\n", time_decrypt_DES_ECB_serial);
	

	//save data
	FILE *cOutput = fopen("ciphertext.txt", "w");
	FILE *dOutput = fopen("decryptedtext.txt", "w");
	if(cOutput == NULL || dOutput == NULL){
		printf("ERROR: Cannot open output files\n");
		exit(1);
	}
	fprintf(cOutput, "%s\n\nEncryption time: %d nanoseconds",cipherContents, time_encrypt_DES_ECB_serial);
	fprintf(dOutput, "%s\n\nDecryption time: %d nanoseconds",decryptedContents, time_decrypt_DES_ECB_serial);




//************************************** ECB Threads ***********************************
	input vals;
	vals.start = 0;
	vals.end = fileSize;
	vals.level = 4;


	//printf("%s\n", cipherContents);
	
	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime

	encryptDES_ECB_threads(&vals);

	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_encrypt_DES_ECB_threads = i * 1000000000 + j;
	//printf("%s\n", cipherContents);
	
	vals.start = 0;
	vals.end = fileSize;
	vals.level = 4;
	
	//printf("%s\n", decryptedContents);
	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime

	decryptDES_ECB_threads(&vals);

	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_decrypt_DES_ECB_threads = i * 1000000000 + j;
	//printf("%s\n", decryptedContents);

	printf("ECB Thread********************************************\n");
	printf("Encryption: %d nanoseconds\n", time_encrypt_DES_ECB_threads);
	printf("Decryption: %d nanoseconds\n", time_decrypt_DES_ECB_threads);




//************************************** CBC Serial ***********************************

	//printf("%s\n", cipherContents);
	
	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime

	encrypt_DES_CBC();

	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_encrypt_DES_CBC = i * 1000000000 + j;
	//printf("%s\n", cipherContents);
	
	//printf("%s\n", decryptedContents);
	if(clock_gettime(CLOCK_REALTIME, &s_starttimer) != 0){
		printf("ERRO: clock gettime failed\n");
		exit(1);
	} // get starttime

	decrypt_DES_CBC();

	if(clock_gettime(CLOCK_REALTIME, &s_endtimer) != 0){
		printf("ERRO: clock_gettime failed\n");
		exit(1);
	} // get endtime
	i = s_endtimer.tv_sec - s_starttimer.tv_sec;
	j = s_endtimer.tv_nsec - s_starttimer.tv_nsec;
	int time_decrypt_DES_CBC = i * 1000000000 + j;
	//printf("%s\n", decryptedContents);

	printf("CBC Serial********************************************\n");
	printf("Encryption: %d nanoseconds\n", time_encrypt_DES_CBC);
	printf("Decryption: %d nanoseconds\n\n", time_decrypt_DES_CBC);
	fclose(cOutput);
	fclose(dOutput);
	free(fileContents);
	free(cipherContents);
	free(decryptedContents);
} // end of main
