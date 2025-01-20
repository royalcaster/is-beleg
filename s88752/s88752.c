#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

void handle_errors(void)
{
	/* Print OpenSSL error messages and abort */
	ERR_print_errors_fp(stderr);
	abort();
}

int decrypt_camellia(const char *cipher_file, const char *key_file, const char *output_file)
{
	FILE *cipher_fp, *key_fp, *output_fp;
	unsigned char *cipher_text, *plain_text;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	long cipher_len;
	int len, plain_len;
	EVP_CIPHER_CTX *ctx;

	/* Open files for reading and writing */
	cipher_fp = fopen(cipher_file, "rb");
	key_fp = fopen(key_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!cipher_fp || !key_fp || !output_fp) {
		perror("File open error");
		return 1;
	}

	/* Get the cipher file length */
	fseek(cipher_fp, 0, SEEK_END);
	cipher_len = ftell(cipher_fp);
	fseek(cipher_fp, 0, SEEK_SET);

	/* Allocate memory for the cipher text */
	cipher_text = malloc(cipher_len);
	if (!cipher_text) {
		perror("Memory allocation error");
		fclose(cipher_fp);
		fclose(key_fp);
		fclose(output_fp);
		return 1;
	}

	/* Read cipher text into buffer */
	fread(cipher_text, 1, cipher_len, cipher_fp);
	fclose(cipher_fp);

	/* Read key and IV from the key file */
	fread(key, 1, EVP_CIPHER_key_length(EVP_camellia_192_cfb128()), key_fp);
	fread(iv, 1, EVP_CIPHER_iv_length(EVP_camellia_192_cfb128()), key_fp);
	fclose(key_fp);

	/* Create a new cipher context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	/* Initialize decryption */
	if (EVP_DecryptInit_ex(ctx, EVP_camellia_192_cfb128(), NULL, key, iv) != 1)
		handle_errors();

	/* Allocate memory for the plain text */
	plain_text = malloc(cipher_len);
	if (!plain_text) {
		perror("Memory allocation error");
		EVP_CIPHER_CTX_free(ctx);
		free(cipher_text);
		fclose(output_fp);
		return 1;
	}

	/* Decrypt the data */
	if (EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_len) != 1)
		handle_errors();
	plain_len = len;

	if (EVP_DecryptFinal_ex(ctx, plain_text + len, &len) != 1)
		handle_errors();
	plain_len += len;

	/* Write the decrypted data to the output file */
	fwrite(plain_text, 1, plain_len, output_fp);

	/* Clean up */
	free(cipher_text);
	free(plain_text);
	EVP_CIPHER_CTX_free(ctx);
	fclose(output_fp);

	return 0;
}

int verify_signature(const char *data_file, const char *sig_file, const char *pubkey_file)
{
	FILE *data_fp, *sig_fp, *pubkey_fp;
	unsigned char *data, *sig;
	long data_len, sig_len;
	EVP_PKEY *pubkey;
	EVP_MD_CTX *mdctx;
	int result;

	/* Open files for reading */
	data_fp = fopen(data_file, "rb");
	sig_fp = fopen(sig_file, "rb");
	pubkey_fp = fopen(pubkey_file, "r");

	if (!data_fp || !sig_fp || !pubkey_fp) {
		perror("File open error");
		return 1;
	}

	/* Get the data file length */
	fseek(data_fp, 0, SEEK_END);
	data_len = ftell(data_fp);
	fseek(data_fp, 0, SEEK_SET);

	/* Allocate memory for data */
	data = malloc(data_len);
	if (!data) {
		perror("Memory allocation error");
		fclose(data_fp);
		fclose(sig_fp);
		fclose(pubkey_fp);
		return 1;
	}
	fread(data, 1, data_len, data_fp);
	fclose(data_fp);

	/* Get the signature length */
	fseek(sig_fp, 0, SEEK_END);
	sig_len = ftell(sig_fp);
	fseek(sig_fp, 0, SEEK_SET);

	/* Allocate memory for signature */
	sig = malloc(sig_len);
	if (!sig) {
		perror("Memory allocation error");
		free(data);
		fclose(sig_fp);
		fclose(pubkey_fp);
		return 1;
	}
	fread(sig, 1, sig_len, sig_fp);
	fclose(sig_fp);

	/* Read the public key */
	pubkey = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
	fclose(pubkey_fp);

	if (!pubkey)
		handle_errors();

	/* Create a new message digest context */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		handle_errors();

	/* Initialize verification */
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha3_512(), NULL, pubkey) != 1)
		handle_errors();

	/* Add data to verify */
	if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
		handle_errors();

	/* Finalize verification */
	result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);

	/* Clean up */
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pubkey);
	free(data);
	free(sig);

	/* Return success or failure */
	return result == 1 ? 0 : 1;
}

void adjust_festive_text(const char *input_file, const char *output_file)
{
	FILE *input_fp, *output_fp;
	unsigned char *data;
	long file_len;

	/* Open input and output files */
	input_fp = fopen(input_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!input_fp || !output_fp) {
		perror("File open error");
		return;
	}

	/* Get the file length */
	fseek(input_fp, 0, SEEK_END);
	file_len = ftell(input_fp);
	fseek(input_fp, 0, SEEK_SET);

	/* Allocate memory for data */
	data = malloc(file_len);
	if (!data) {
		perror("Memory allocation error");
		fclose(input_fp);
		fclose(output_fp);
		return;
	}
	fread(data, 1, file_len, input_fp);
	fclose(input_fp);

	/* Adjust text according to festive rules */
	for (long i = 0; i < file_len; i++) {
		if (data[i] == 'O' && data[i + 1] == 'O') {
			fwrite("eier", 1, 4, output_fp);
			i++;
		} else if (data[i] == 'O') {
			fwrite("ei", 1, 2, output_fp);
		} else {
			fwrite(&data[i], 1, 1, output_fp);
		}
	}

	/* Clean up */
	free(data);
	fclose(output_fp);
}

int encrypt_aes_ofb(const char *input_file, const char *key_file, const char *output_file)
{
	FILE *input_fp, *key_fp, *output_fp;
	unsigned char *input_data, *cipher_data;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	long input_len;
	int len, cipher_len;
	EVP_CIPHER_CTX *ctx;

	/* Open files */
	input_fp = fopen(input_file, "rb");
	key_fp = fopen(key_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!input_fp || !key_fp || !output_fp) {
		perror("File open error");
		return 1;
	}

	/* Get input file length */
	fseek(input_fp, 0, SEEK_END);
	input_len = ftell(input_fp);
	fseek(input_fp, 0, SEEK_SET);

	/* Allocate memory for input data */
	input_data = malloc(input_len);
	if (!input_data) {
		perror("Memory allocation error");
		fclose(input_fp);
		fclose(key_fp);
		fclose(output_fp);
		return 1;
	}
	fread(input_data, 1, input_len, input_fp);
	fclose(input_fp);

	/* Read key and IV */
	fread(key, 1, EVP_CIPHER_key_length(EVP_aes_128_ofb()), key_fp);
	fread(iv, 1, EVP_CIPHER_iv_length(EVP_aes_128_ofb()), key_fp);
	fclose(key_fp);

	/* Create encryption context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	/* Initialize encryption */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv) != 1)
		handle_errors();

	/* Allocate memory for cipher data */
	cipher_data = malloc(input_len + EVP_CIPHER_block_size(EVP_aes_128_ofb()));
	if (!cipher_data) {
		perror("Memory allocation error");
		EVP_CIPHER_CTX_free(ctx);
		free(input_data);
		fclose(output_fp);
		return 1;
	}

	/* Encrypt the data */
	if (EVP_EncryptUpdate(ctx, cipher_data, &len, input_data, input_len) != 1)
		handle_errors();
	cipher_len = len;

	if (EVP_EncryptFinal_ex(ctx, cipher_data + len, &len) != 1)
		handle_errors();
	cipher_len += len;

	/* Write encrypted data */
	fwrite(cipher_data, 1, cipher_len, output_fp);

	/* Clean up */
	free(input_data);
	free(cipher_data);#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

void handle_errors(void)
{
	/* Print OpenSSL error messages and abort */
	ERR_print_errors_fp(stderr);
	abort();
}

int decrypt_camellia(const char *cipher_file, const char *key_file, const char *output_file, int *output_len)
{
	FILE *cipher_fp, *key_fp, *output_fp;
	unsigned char *cipher_text, *plain_text;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	long cipher_len;
	int len, plain_len;
	EVP_CIPHER_CTX *ctx;

	/* Open files */
	cipher_fp = fopen(cipher_file, "rb");
	key_fp = fopen(key_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!cipher_fp || !key_fp || !output_fp) {
		perror("File open error");
		return 1;
	}

	/* Determine the cipher text length */
	fseek(cipher_fp, 0, SEEK_END);
	cipher_len = ftell(cipher_fp);
	fseek(cipher_fp, 0, SEEK_SET);

	cipher_text = malloc(cipher_len);
	if (!cipher_text) {
		perror("Memory allocation error");
		fclose(cipher_fp);
		fclose(key_fp);
		fclose(output_fp);
		return 1;
	}
	fread(cipher_text, 1, cipher_len, cipher_fp);
	fclose(cipher_fp);

	/* Read key and IV */
	fread(key, 1, EVP_CIPHER_key_length(EVP_camellia_192_cfb128()), key_fp);
	fread(iv, 1, EVP_CIPHER_iv_length(EVP_camellia_192_cfb128()), key_fp);
	fclose(key_fp);

	/* Create and initialize the cipher context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	if (1 != EVP_DecryptInit_ex(ctx, EVP_camellia_192_cfb128(), NULL, key, iv))
		handle_errors();

	plain_text = malloc(cipher_len); /* Allocate buffer for decrypted text */
	if (!plain_text) {
		perror("Memory allocation error");
		EVP_CIPHER_CTX_free(ctx);
		free(cipher_text);
		fclose(output_fp);
		return 1;
	}

	/* Perform decryption */
	if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_len))
		handle_errors();
	plain_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len))
		handle_errors();
	plain_len += len;

	/* Write the decrypted data */
	fwrite(plain_text, 1, plain_len, output_fp);
	fclose(output_fp);

	/* Calculate encrypted length as a multiple of the block size */
	int block_size = EVP_CIPHER_block_size(EVP_aes_128_ofb());
	int encrypted_len = (plain_len % block_size == 0) ? plain_len : ((plain_len / block_size + 1) * block_size);

	*output_len = encrypted_len; // Use the calculated encrypted length

	/* Clean up */
	free(cipher_text);
	free(plain_text);
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

int verify_signature(const char *data_file, const char *sig_file, const char *pubkey_file)
{
	FILE *data_fp, *sig_fp, *pubkey_fp;
	unsigned char *data, *sig;
	long data_len, sig_len;
	EVP_PKEY *pubkey;
	EVP_MD_CTX *mdctx;
	int result;

	/* Open files for reading */
	data_fp = fopen(data_file, "rb");
	sig_fp = fopen(sig_file, "rb");
	pubkey_fp = fopen(pubkey_file, "r");

	if (!data_fp || !sig_fp || !pubkey_fp) {
		perror("File open error");
		return 1;
	}

	/* Get the data file length */
	fseek(data_fp, 0, SEEK_END);
	data_len = ftell(data_fp);
	fseek(data_fp, 0, SEEK_SET);

	/* Allocate memory for data */
	data = malloc(data_len);
	if (!data) {
		perror("Memory allocation error");
		fclose(data_fp);
		fclose(sig_fp);
		fclose(pubkey_fp);
		return 1;
	}
	fread(data, 1, data_len, data_fp);
	fclose(data_fp);

	/* Get the signature length */
	fseek(sig_fp, 0, SEEK_END);
	sig_len = ftell(sig_fp);
	fseek(sig_fp, 0, SEEK_SET);

	/* Allocate memory for signature */
	sig = malloc(sig_len);
	if (!sig) {
		perror("Memory allocation error");
		free(data);
		fclose(sig_fp);
		fclose(pubkey_fp);
		return 1;
	}
	fread(sig, 1, sig_len, sig_fp);
	fclose(sig_fp);

	/* Read the public key */
	pubkey = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
	fclose(pubkey_fp);

	if (!pubkey)
		handle_errors();

	/* Create a new message digest context */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		handle_errors();

	/* Initialize verification */
	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha3_512(), NULL, pubkey) != 1)
		handle_errors();

	/* Add data to verify */
	if (EVP_DigestVerifyUpdate(mdctx, data, data_len) != 1)
		handle_errors();

	/* Finalize verification */
	result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);

	/* Clean up */
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pubkey);
	free(data);
	free(sig);

	/* Return success or failure */
	return result == 1 ? 0 : 1;
}

long adjust_festive_text(const char *input_file, const char *output_file)
{
	FILE *input_fp, *output_fp;
	unsigned char *data;
	long file_len, adjusted_len = 0;

	input_fp = fopen(input_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!input_fp || !output_fp) {
		perror("File open error");
		return -1;
	}

	/* Get the file length */
	fseek(input_fp, 0, SEEK_END);
	file_len = ftell(input_fp);
	fseek(input_fp, 0, SEEK_SET);

	/* Allocate memory for data */
	data = malloc(file_len);
	if (!data) {
		perror("Memory allocation error");
		fclose(input_fp);
		fclose(output_fp);
		return -1;
	}
	fread(data, 1, file_len, input_fp);
	fclose(input_fp);

	/* Adjust text according to festive rules */
	for (long i = 0; i < file_len; i++) {
		if (data[i] == 'O' && data[i + 1] == 'O') {
			fwrite("eier", 1, 4, output_fp);
			adjusted_len += 4;
			i++;
		} else if (data[i] == 'O') {
			fwrite("ei", 1, 2, output_fp);
			adjusted_len += 2;
		} else {
			fwrite(&data[i], 1, 1, output_fp);
			adjusted_len++;
		}
	}

	free(data);
	fclose(output_fp);

	return adjusted_len;
}

int encrypt_aes_ofb(const char *input_file, const char *key_file, const char *output_file)
{
	FILE *input_fp, *key_fp, *output_fp;
	unsigned char *input_data, *cipher_data;
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	long input_len;
	int len, cipher_len;
	EVP_CIPHER_CTX *ctx;

	/* Open files */
	input_fp = fopen(input_file, "rb");
	key_fp = fopen(key_file, "rb");
	output_fp = fopen(output_file, "wb");

	if (!input_fp || !key_fp || !output_fp) {
		perror("File open error");
		return 1;
	}

	/* Get input file length */
	fseek(input_fp, 0, SEEK_END);
	input_len = ftell(input_fp);
	fseek(input_fp, 0, SEEK_SET);

	/* Allocate memory for input data */
	input_data = malloc(input_len);
	if (!input_data) {
		perror("Memory allocation error");
		fclose(input_fp);
		fclose(key_fp);
		fclose(output_fp);
		return 1;
	}
	fread(input_data, 1, input_len, input_fp);
	fclose(input_fp);

	/* Read key and IV */
	fread(key, 1, EVP_CIPHER_key_length(EVP_aes_128_ofb()), key_fp);
	fread(iv, 1, EVP_CIPHER_iv_length(EVP_aes_128_ofb()), key_fp);
	fclose(key_fp);

	/* Create encryption context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	/* Initialize encryption */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv) != 1)
		handle_errors();

	/* Allocate memory for cipher data */
	cipher_data = malloc(input_len + EVP_CIPHER_block_size(EVP_aes_128_ofb()));
	if (!cipher_data) {
		perror("Memory allocation error");
		EVP_CIPHER_CTX_free(ctx);
		free(input_data);
		fclose(output_fp);
		return 1;
	}

	/* Encrypt the data */
	if (EVP_EncryptUpdate(ctx, cipher_data, &len, input_data, input_len) != 1)
		handle_errors();
	cipher_len = len;

	if (EVP_EncryptFinal_ex(ctx, cipher_data + len, &len) != 1)
		handle_errors();
	cipher_len += len;

	/* Write encrypted data */
	fwrite(cipher_data, 1, cipher_len, output_fp);

	/* Clean up */
	free(input_data);
	free(cipher_data);
	EVP_CIPHER_CTX_free(ctx);
	fclose(output_fp);

	return 0;
}

int main(void)
{
	int output_len1, output_len2;

	/* Decrypt files */
	if (decrypt_camellia("s88752-cipher1.bin", "s88752-key1.bin", "output1.bin", &output_len1) != 0) {
		fprintf(stderr, "Failed to decrypt s88752-cipher1.bin\n");
		return 1;
	}

	if (decrypt_camellia("s88752-cipher2.bin", "s88752-key1.bin", "output2.bin", &output_len2) != 0) {
		fprintf(stderr, "Failed to decrypt s88752-cipher2.bin\n");
		return 1;
	}

	printf("Decryption completed successfully. Lengths: %d, %d\n", output_len1, output_len2);

	const char *matched_file = NULL;

	/* Verify signatures */
	if (verify_signature("output1.bin", "s88752-sig.bin", "dsapub.pem") == 0) {
		printf("Signature matches output1.bin.\n");
		matched_file = "output1.bin";
	} else if (verify_signature("output2.bin", "s88752-sig.bin", "dsapub.pem") == 0) {
		printf("Signature matches output2.bin.\n");
		matched_file = "output2.bin";
	} else {
		fprintf(stderr, "Signature does not match any output file.\n");
		return 1;
	}

	/* Process matched file */
	if (matched_file) {
		long adjusted_len = adjust_festive_text(matched_file, "cleaned_output.bin");
		if (adjusted_len < 0) {
			fprintf(stderr, "Error adjusting festive text\n");
			return 1;
		}
		printf("Festive text adjustment completed. Adjusted length: %ld\n", adjusted_len);

		if (encrypt_aes_ofb("cleaned_output.bin", "s88752-key2.bin", "s88752-result.bin") != 0) {
			fprintf(stderr, "Failed to encrypt cleaned_output.bin\n");
			return 1;
		}

		printf("Encryption completed successfully.\n");
	}

	return 0;
}

	EVP_CIPHER_CTX_free(ctx);
	fclose(output_fp);

	return 0;
}

int main(void)
{
	/* Decrypt files */
	if (decrypt_camellia("s88752-cipher1.bin", "s88752-key1.bin", "output1.bin") != 0) {
		fprintf(stderr, "Failed to decrypt s88752-cipher1.bin\n");
		return 1;
	}

	if (decrypt_camellia("s88752-cipher2.bin", "s88752-key1.bin", "output2.bin") != 0) {
		fprintf(stderr, "Failed to decrypt s88752-cipher2.bin\n");
		return 1;
	}

	printf("Decryption completed successfully.\n");

	const char *matched_file = NULL;

	/* Verify signatures */
	if (verify_signature("output1.bin", "s88752-sig.bin", "dsapub.pem") == 0) {
		printf("Signature matches output1.bin.\n");
		matched_file = "output1.bin";
	} else if (verify_signature("output2.bin", "s88752-sig.bin", "dsapub.pem") == 0) {
		printf("Signature matches output2.bin.\n");
		matched_file = "output2.bin";
	} else {
		fprintf(stderr, "Signature does not match any output file.\n");
		return 1;
	}

	/* Process matched file */
	if (matched_file) {
		adjust_festive_text(matched_file, "cleaned_output.bin");
		printf("Festive text adjustment completed.\n");

		if (encrypt_aes_ofb("cleaned_output.bin", "s88752-key2.bin", "s88752-result.bin") != 0) {
			fprintf(stderr, "Failed to encrypt cleaned_output.bin\n");
			return 1;
		}

		printf("Encryption completed successfully.\n");
	}

	return 0;
}