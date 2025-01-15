#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 4096

int verbose = 0; // Global flag for verbose output

/*
 * Print OpenSSL error messages and terminate the program.
 */
void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Print messages if verbose mode is enabled.
 */
void log_verbose(const char *message, const char *detail)
{
    if (verbose) {
        if (detail)
            printf("[VERBOSE] %s: %s\n", message, detail);
        else
            printf("[VERBOSE] %s\n", message);
    }
}

/*
 * Print binary or textual data in a human-readable format.
 */
void log_data(const char *label, const unsigned char *data, size_t len)
{
    if (!verbose)
        return;

    printf("[VERBOSE] %s (length: %zu):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126) // Printable characters
            printf("%c", data[i]);
        else
            printf("\\x%02x", data[i]);
    }
    printf("\n");
}

/*
 * Function prototypes for encrypt_data and decrypt_data
 */
void encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                  const unsigned char *key, const unsigned char *iv,
                  unsigned char **ciphertext, int *ciphertext_len,
                  const EVP_CIPHER *cipher_type);

void decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *key, const unsigned char *iv,
                  unsigned char **plaintext, size_t *plaintext_len,
                  const EVP_CIPHER *cipher_type);

/*
 * Read the contents of a binary file into memory.
 */
void read_file(const char *filename, unsigned char **data, size_t *len)
{
    log_verbose("Reading file", filename);
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *len = ftell(file);
    rewind(file);

    *data = malloc(*len);
    if (!*data) {
        perror("Memory allocation error");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (fread(*data, 1, *len, file) != *len) {
        perror("Error reading file");
        free(*data);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "File size: %zu bytes", *len);
    log_verbose("File read successfully", buffer);
    log_data("File content", *data, *len);
}

/*
 * Write binary data to a file.
 */
void write_file(const char *filename, const unsigned char *data, size_t len)
{
    log_verbose("Writing to file", filename);
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    if (fwrite(data, 1, len, file) != len) {
        perror("Error writing to file");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "File size: %zu bytes", len);
    log_verbose("File written successfully", buffer);
    log_data("Written file content", data, len);
}

/*
 * Decrypt data using a specified cipher, key, and IV.
 */
void decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                  const unsigned char *key, const unsigned char *iv,
                  unsigned char **plaintext, size_t *plaintext_len,
                  const EVP_CIPHER *cipher_type)
{
    log_verbose("Decrypting data with cipher", EVP_CIPHER_name(cipher_type));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handle_errors();

    if (EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1)
        handle_errors();

    *plaintext = malloc(ciphertext_len + EVP_CIPHER_block_size(cipher_type));
    if (!*plaintext)
        handle_errors();

    int len;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) != 1)
        handle_errors();
    *plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1)
        handle_errors();
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "Decrypted data size: %zu bytes", *plaintext_len);
    log_verbose("Decryption complete", buffer);
    log_data("Decrypted content", *plaintext, *plaintext_len);
}

/*
 * Encrypt data using a specified cipher, key, and IV.
 */
void encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                  const unsigned char *key, const unsigned char *iv,
                  unsigned char **ciphertext, int *ciphertext_len,
                  const EVP_CIPHER *cipher_type)
{
    log_verbose("Encrypting data with cipher", EVP_CIPHER_name(cipher_type));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handle_errors();

    if (EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv) != 1)
        handle_errors();

    *ciphertext = malloc(plaintext_len + EVP_CIPHER_block_size(cipher_type));
    if (!*ciphertext)
        handle_errors();

    int len;
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1)
        handle_errors();
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1)
        handle_errors();
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "Encrypted data size: %d bytes", *ciphertext_len);
    log_verbose("Encryption complete", buffer);
    log_data("Encrypted content", *ciphertext, *ciphertext_len);
}

/*
 * Verify a digital signature using a public key.
 */
int verify_signature(const unsigned char *data, size_t data_len,
                     const unsigned char *signature, size_t sig_len,
                     const char *pubkey_file)
{
    log_verbose("Verifying signature using public key file", pubkey_file);
    FILE *pubkey_fp = fopen(pubkey_file, "r");
    if (!pubkey_fp) {
        perror("Error opening public key file");
        exit(EXIT_FAILURE);
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
    fclose(pubkey_fp);

    if (!pubkey)
        handle_errors();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        handle_errors();

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha3_512(), NULL, pubkey) != 1)
        handle_errors();

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1)
        handle_errors();

    int result = EVP_DigestVerifyFinal(ctx, signature, sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    log_verbose(result == 1 ? "Signature verification successful" : "Signature verification failed", NULL);
    return result == 1;
}

/*
 * Remove the text up to the null character in the valid plaintext.
 */
void remove_festivity_text(unsigned char *data, size_t *len)
{
    log_verbose("Removing festivity text", NULL);

    size_t pos = 0;

    /* Find the null character ('\0') */
    while (pos < *len && data[pos] != '\0') {
        pos++;
    }

    if (pos < *len) {
        printf("Removed text: ");
        fwrite(data, 1, pos, stdout);
        printf("\n");

        pos++; /* Include the null character */
        memmove(data, data + pos, *len - pos);
        *len -= pos;
    }

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "Processed data size after removal: %zu bytes", *len);
    log_verbose("Festivity text removed", buffer);
    log_data("Remaining content", data, *len);
}

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            log_verbose("Verbose mode enabled", NULL);
        }
    }

    unsigned char *cipher1, *cipher2, *key1, *key2, *signature, *plaintext1, *plaintext2, *ciphertext;
    size_t cipher1_len, cipher2_len, key1_len, key2_len, signature_len, plaintext1_len, plaintext2_len;
    int ciphertext_len;

    read_file("s88752-cipher1.bin", &cipher1, &cipher1_len);
    read_file("s88752-cipher2.bin", &cipher2, &cipher2_len);
    read_file("s88752-key1.bin", &key1, &key1_len);
    read_file("s88752-key2.bin", &key2, &key2_len);
    read_file("s88752-sig.bin", &signature, &signature_len);

    const EVP_CIPHER *camellia = EVP_camellia_192_cfb128();
    decrypt_data(cipher1, cipher1_len, key1, key1 + EVP_CIPHER_key_length(camellia),
                 &plaintext1, &plaintext1_len, camellia);
    decrypt_data(cipher2, cipher2_len, key1, key1 + EVP_CIPHER_key_length(camellia),
                 &plaintext2, &plaintext2_len, camellia);

    int matches1 = verify_signature(plaintext1, plaintext1_len, signature, signature_len, "dsapub.pem");
    int matches2 = verify_signature(plaintext2, plaintext2_len, signature, signature_len, "dsapub.pem");

    unsigned char *valid_plaintext;
    size_t valid_plaintext_len;

    if (matches1) {
        valid_plaintext = plaintext1;
        valid_plaintext_len = plaintext1_len;
    } else if (matches2) {
        valid_plaintext = plaintext2;
        valid_plaintext_len = plaintext2_len;
    } else {
        fprintf(stderr, "Error: No valid plaintext matches the signature.\n");
        exit(EXIT_FAILURE);
    }

    remove_festivity_text(valid_plaintext, &valid_plaintext_len);

    printf("Modified plaintext before encryption:\n");
    fwrite(valid_plaintext, 1, valid_plaintext_len, stdout);
    printf("\n");

    const EVP_CIPHER *aes = EVP_aes_128_ofb();
    encrypt_data(valid_plaintext, valid_plaintext_len, key2, key2 + EVP_CIPHER_key_length(aes),
                 &ciphertext, &ciphertext_len, aes);

    write_file("s88752-result.bin", ciphertext, ciphertext_len);

    free(cipher1);
    free(cipher2);
    free(key1);
    free(key2);
    free(signature);
    free(plaintext1);
    free(plaintext2);
    free(ciphertext);

    log_verbose("Program completed successfully.", NULL);
    return 0;
}
