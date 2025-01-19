#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt_camellia(const char *cipher_file, const char *key_file, const char *output_file) {
    FILE *cipher_fp = fopen(cipher_file, "rb");
    FILE *key_fp = fopen(key_file, "rb");
    FILE *output_fp = fopen(output_file, "wb");

    if (!cipher_fp || !key_fp || !output_fp) {
        perror("File open error");
        return 1;
    }

    fseek(cipher_fp, 0, SEEK_END);
    long cipher_len = ftell(cipher_fp);
    fseek(cipher_fp, 0, SEEK_SET);

    unsigned char *cipher_text = malloc(cipher_len);
    if (!cipher_text) {
        perror("Memory allocation error");
        fclose(cipher_fp);
        fclose(key_fp);
        fclose(output_fp);
        return 1;
    }

    fread(cipher_text, 1, cipher_len, cipher_fp);
    fclose(cipher_fp);

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    fread(key, 1, EVP_CIPHER_key_length(EVP_camellia_192_cfb128()), key_fp);
    fread(iv, 1, EVP_CIPHER_iv_length(EVP_camellia_192_cfb128()), key_fp);
    fclose(key_fp);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_camellia_192_cfb128(), NULL, key, iv))
        handle_errors();

    unsigned char *plain_text = malloc(cipher_len);
    if (!plain_text) {
        perror("Memory allocation error");
        EVP_CIPHER_CTX_free(ctx);
        free(cipher_text);
        fclose(output_fp);
        return 1;
    }

    int len;
    int plain_len;

    if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher_text, cipher_len))
        handle_errors();
    plain_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len))
        handle_errors();
    plain_len += len;

    fwrite(plain_text, 1, plain_len, output_fp);

    free(cipher_text);
    free(plain_text);
    EVP_CIPHER_CTX_free(ctx);
    fclose(output_fp);

    return 0;
}

int verify_signature(const char *data_file, const char *sig_file, const char *pubkey_file) {
    FILE *data_fp = fopen(data_file, "rb");
    FILE *sig_fp = fopen(sig_file, "rb");
    FILE *pubkey_fp = fopen(pubkey_file, "r");

    if (!data_fp || !sig_fp || !pubkey_fp) {
        perror("File open error");
        return 1;
    }

    fseek(data_fp, 0, SEEK_END);
    long data_len = ftell(data_fp);
    fseek(data_fp, 0, SEEK_SET);

    unsigned char *data = malloc(data_len);
    if (!data) {
        perror("Memory allocation error");
        fclose(data_fp);
        fclose(sig_fp);
        fclose(pubkey_fp);
        return 1;
    }

    fread(data, 1, data_len, data_fp);
    fclose(data_fp);

    fseek(sig_fp, 0, SEEK_END);
    long sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);

    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        perror("Memory allocation error");
        free(data);
        fclose(sig_fp);
        fclose(pubkey_fp);
        return 1;
    }

    fread(sig, 1, sig_len, sig_fp);
    fclose(sig_fp);

    EVP_PKEY *pubkey = PEM_read_PUBKEY(pubkey_fp, NULL, NULL, NULL);
    fclose(pubkey_fp);

    if (!pubkey) handle_errors();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha3_512(), NULL, pubkey))
        handle_errors();

    if (1 != EVP_DigestVerifyUpdate(mdctx, data, data_len))
        handle_errors();

    int result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);
    free(data);
    free(sig);

    return result == 1 ? 0 : 1;
}

void adjust_festive_text(const char *input_file, const char *output_file) {
    FILE *input_fp = fopen(input_file, "rb");
    FILE *output_fp = fopen(output_file, "wb");

    if (!input_fp || !output_fp) {
        perror("File open error");
        return;
    }

    fseek(input_fp, 0, SEEK_END);
    long file_len = ftell(input_fp);
    fseek(input_fp, 0, SEEK_SET);

    unsigned char *data = malloc(file_len);
    if (!data) {
        perror("Memory allocation error");
        fclose(input_fp);
        fclose(output_fp);
        return;
    }

    fread(data, 1, file_len, input_fp);
    fclose(input_fp);

    for (long i = 0; i < file_len; i++) {
        if (data[i] == '\0') break;
        if (data[i] == 'O' && data[i + 1] == 'O') {
            fwrite("eier", 1, 4, output_fp);
            i++;
        } else if (data[i] == 'O') {
            fwrite("ei", 1, 2, output_fp);
        } else {
            fwrite(&data[i], 1, 1, output_fp);
        }
    }

    fwrite(data + strlen((char *)data) + 1, 1, file_len - strlen((char *)data) - 1, output_fp);

    free(data);
    fclose(output_fp);
}

int encrypt_aes_ofb(const char *input_file, const char *key_file, const char *output_file) {
    FILE *input_fp = fopen(input_file, "rb");
    FILE *key_fp = fopen(key_file, "rb");
    FILE *output_fp = fopen(output_file, "wb");

    if (!input_fp || !key_fp || !output_fp) {
        perror("File open error");
        return 1;
    }

    fseek(input_fp, 0, SEEK_END);
    long input_len = ftell(input_fp);
    fseek(input_fp, 0, SEEK_SET);

    unsigned char *input_data = malloc(input_len);
    if (!input_data) {
        perror("Memory allocation error");
        fclose(input_fp);
        fclose(key_fp);
        fclose(output_fp);
        return 1;
    }

    fread(input_data, 1, input_len, input_fp);
    fclose(input_fp);

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    fread(key, 1, EVP_CIPHER_key_length(EVP_aes_128_ofb()), key_fp);
    fread(iv, 1, EVP_CIPHER_iv_length(EVP_aes_128_ofb()), key_fp);
    fclose(key_fp);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
        handle_errors();

    unsigned char *cipher_data = malloc(input_len + EVP_CIPHER_block_size(EVP_aes_128_ofb()));
    if (!cipher_data) {
        perror("Memory allocation error");
        EVP_CIPHER_CTX_free(ctx);
        free(input_data);
        fclose(output_fp);
        return 1;
    }

    int len;
    int cipher_len;

    if (1 != EVP_EncryptUpdate(ctx, cipher_data, &len, input_data, input_len))
        handle_errors();
    cipher_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipher_data + len, &len))
        handle_errors();
    cipher_len += len;

    fwrite(cipher_data, 1, cipher_len, output_fp);

    free(input_data);
    free(cipher_data);
    EVP_CIPHER_CTX_free(ctx);
    fclose(output_fp);

    return 0;
}

int main() {
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
