#define _OPENSSL_API_COMPAT 10102
#include <openssl/des.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function to convert a binary array to a hexadecimal string
 void binaryToHex(const unsigned char *input, int length, char *output) {
     static const char *hex = "0123456789ABCDEF";
     for (int i = 0; i < length; i++) {
            output[i * 2] = hex[(input[i] >> 4) & 0xF];
            output[i * 2 + 1] = hex[input[i] & 0xF];
     }
     output[length * 2] = '\0';
} // end of binaryToHex

void binaryToASCII(const unsigned char *input, int length, char *output) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i];
    }
    output[length] = '\0';
}

int main(void){
	DES_cblock key;
	DES_cblock plaintext, ciphertext, decrypted_text;

	const char *keyStr = "ABCDEFGH";
	if(strlen(keyStr) != 8){
		printf("ERROR: Key length is not 8\n");
		exit(1);
	}
	unsigned char keyData[8]; 
	for(int i = 0; i < 8; i++){
		sscanf(keyStr + 2 * i, "%shhx", &keyData[i]);
	}
	memcpy(key, keyData, sizeof(keyData));
	// end of key initialization
	
	const char *plaintextStr = "HELLO!!!";
	if(strlen(plaintextStr) != 8){
		printf("ERROR: Plaintext length is not 8\n");
		exit(1);
	}
	unsigned char plaintextData[8]; 
	for(int i = 0; i < 8; i++){
		sscanf(&plaintextStr[i], "%shhx", &plaintextData[i]);
	}
	memcpy(plaintext, plaintextData, sizeof(plaintextData));

	
	DES_key_schedule key_schedule;
	
	DES_set_key((const_DES_cblock *)key, &key_schedule);

	DES_ecb_encrypt(&plaintext, &ciphertext, &key_schedule, DES_ENCRYPT);
	DES_ecb_encrypt(&ciphertext, &decrypted_text, &key_schedule, DES_DECRYPT);

	// Convert the binary data back to ascii strings
	char ciphertext_ascii[9]; // 8 bytes of data plus null terminator
	char decrypted_ascii[9];
	char plaintext_ascii[9];	

	binaryToASCII(plaintext, 8, plaintext_ascii);
	binaryToASCII(ciphertext, 8, ciphertext_ascii);
	binaryToASCII(decrypted_text, 8, decrypted_ascii);

	printf("Plaintext:      %s\n", plaintext_ascii);
	printf("Ciphertext:     %s\n", ciphertext_ascii);
	printf("Decrypted_text: %s\n", decrypted_ascii);
	
} // end of main
