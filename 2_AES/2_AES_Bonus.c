/*
    references:

    https://github.com/wolfSSL/wolfssl/wiki/Building-wolfSSL
    https://github.com/wolfSSL/wolfssl/blob/master/wrapper/python/wolfcrypt/README.rst
    https://csrc.nist.gov/publications/detail/fips/197/final
    https://en.wikipedia.org/wiki/AES_instruction_set
    https://stackoverflow.com/questions/3716691/relation-between-input-and-ciphertext-length-in-aes
    https://www.wolfssl.com/docs/wolfssl-manual/ch10/
    https://www.wolfssl.com/doxygen/group__AES.html
    https://gist.github.com/acapola/d5b940da024080dfaf5f
    https://stackoverflow.com/questions/32297088/how-to-implement-aes128-encryption-decryption-using-aes-ni-instructions-and-gcc

    --------------------------------------------------------------------------------

    build wolfCrypt (and wolfSSL) on Ubuntu 18.04 (x86 PC) with AES-CTR enabled (DISABLED by default):

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-aesctr
    make
    sudo make install

    sudo ldconfig

    --------------------------------------------------------------------------------

    build this code on Ubuntu 18.04 (x86 PC) with:
    $gcc 2_AES_Bonus.c -o exe -lm -lwolfssl -g -O0 -Wall -msse2 -msse -march=native -maes

    then run the executable on Ubuntu 18.04 (x86 PC) with:
    $LD_LIBRARY_PATH=/usr/local/lib ./exe

    --------------------------------------------------------------------------------

    note:

    weird bug appears, when

    wc_AesSetKeyDirect(&aes_enc,
                       key,
                       AES_128_KEY_SIZE,
                       NULL,
                       AES_ENCRYPTION);

    is called after

    byte input[AES_BLOCK_SIZE] =
        {0x32, 0x43, 0xf6, 0xa8,
         0x88, 0x5a, 0x30, 0x8d,
         0x31, 0x31, 0x98, 0xa2,
         0xe0, 0x37, 0x07, 0x34};

    is initialized. "input" changes data to:

    input ==
        {0x32, 0x43, 0xf6, 0xa8,
         0x00, 0x00, 0x00, 0x00,
         0x31, 0x31, 0x98, 0xa2,
         0xe0, 0x37, 0x07, 0x34};

    The reason is not known.

    --------------------------------------------------------------------------------

    hardware used (german notation):

    CPU(s):                        4
    Liste der Online-CPU(s):       0-3
    Thread(s) pro Kern:            2
    Kern(e) pro Socket:            2
    Modellname:                    Intel(R) Core(TM) i3 CPU       U 380  @ 1.33GHz
    CPU MHz:                       1053.629
    Maximale Taktfrequenz der CPU: 1333,0000
    Minimale Taktfrequenz der CPU: 666,0000
    L1d Cache:                     32K
    L1i Cache:                     32K
    L2 Cache:                      256K
    L3 Cache:                      3072K

    --------------------------------------------------------------------------------

    Can not finish the bonus task!
    
    The Intel(R) Core(TM) i3 CPU U 380 does not support Intel(R) AES New Instructions.
    Further informations: 
    https://ark.intel.com/content/www/de/de/ark/products/50028/intel-core-i3-380um-processor-3m-cache-1-33-ghz.html
*/

#include <stdio.h>
#include <stdint.h> //for int8_t
#include <string.h> //for memcmp
#include <time.h>
#include <wmmintrin.h> //for intrinsics for AES-NI

#define WOLFSSL_AES_DIRECT

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/aes.h>

#define LOOP_CYCLES 10000000 // amount of "wc_AesEncryptDirect() and wc_AesDecryptDirect() loop" cycles

/*- hardware accelerated code ----------------------------------------------------*/
/*- from https://gist.github.com/acapola/d5b940da024080dfaf5f --------------------*/

//compile using gcc and following arguments: -g;-O0;-Wall;-msse2;-msse;-march=native;-maes

//internal stuff

//macros
#define DO_ENC_BLOCK(m, k)                  \
    do                                      \
    {                                       \
        m = _mm_xor_si128(m, k[0]);         \
        m = _mm_aesenc_si128(m, k[1]);      \
        m = _mm_aesenc_si128(m, k[2]);      \
        m = _mm_aesenc_si128(m, k[3]);      \
        m = _mm_aesenc_si128(m, k[4]);      \
        m = _mm_aesenc_si128(m, k[5]);      \
        m = _mm_aesenc_si128(m, k[6]);      \
        m = _mm_aesenc_si128(m, k[7]);      \
        m = _mm_aesenc_si128(m, k[8]);      \
        m = _mm_aesenc_si128(m, k[9]);      \
        m = _mm_aesenclast_si128(m, k[10]); \
    } while (0)

#define DO_DEC_BLOCK(m, k)                  \
    do                                      \
    {                                       \
        m = _mm_xor_si128(m, k[10 + 0]);    \
        m = _mm_aesdec_si128(m, k[10 + 1]); \
        m = _mm_aesdec_si128(m, k[10 + 2]); \
        m = _mm_aesdec_si128(m, k[10 + 3]); \
        m = _mm_aesdec_si128(m, k[10 + 4]); \
        m = _mm_aesdec_si128(m, k[10 + 5]); \
        m = _mm_aesdec_si128(m, k[10 + 6]); \
        m = _mm_aesdec_si128(m, k[10 + 7]); \
        m = _mm_aesdec_si128(m, k[10 + 8]); \
        m = _mm_aesdec_si128(m, k[10 + 9]); \
        m = _mm_aesdeclast_si128(m, k[0]);  \
    } while (0)

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i key_schedule[20]; //the expanded key

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

//public API
void aes128_load_key(int8_t *enc_key)
{
    key_schedule[0] = _mm_loadu_si128((const __m128i *)enc_key);
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);

    // generate decryption keys in reverse order.
    // k[10] is shared by last encryption and first decryption rounds
    // k[0] is shared by first encryption round and last decryption round (and is the original user key)
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
    key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
    key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
    key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
    key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
    key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
    key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
    key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
    key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

void aes128_enc(int8_t *plainText, int8_t *cipherText)
{
    __m128i m = _mm_loadu_si128((__m128i *)plainText);

    DO_ENC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *)cipherText, m);
}

void aes128_dec(int8_t *cipherText, int8_t *plainText)
{
    __m128i m = _mm_loadu_si128((__m128i *)cipherText);

    DO_DEC_BLOCK(m, key_schedule);

    _mm_storeu_si128((__m128i *)plainText, m);
}

//return 0 if no error
//1 if encryption failed
//2 if decryption failed
//3 if both failed
int aes128_self_test(void)
{
    int8_t plain[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    int8_t enc_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    int8_t cipher[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    int8_t computed_cipher[16];
    int8_t computed_plain[16];
    int out = 0;
    aes128_load_key(enc_key);
    aes128_enc(plain, computed_cipher);
    aes128_dec(cipher, computed_plain);
    if (memcmp(cipher, computed_cipher, sizeof(cipher)))
        out = 1;
    if (memcmp(plain, computed_plain, sizeof(plain)))
        out |= 2;
    return out;
}

/*--------------------------------------------------------------------------------*/

void print_aes_block_in_hex(byte *data) // printing the "data"-byte-array with a length of "AES_BLOCK_SIZE" in hex
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        printf("%02x ", data[i]);

        if ((((i + 1) % 4) == 0))
        {
            printf("\n");
        }
    }
}

void print_aes_key(byte *key) // "print_aes_block_in_hex()"-wrapper
{
    printf("key:\n");
    print_aes_block_in_hex(key);
    printf("\n");
}

void print_aes_input(byte *input) // "print_aes_block_in_hex()"-wrapper
{
    printf("input:\n");
    print_aes_block_in_hex(input);
    printf("\n");
}

void print_aes_output(byte *output) // "print_aes_block_in_hex()"-wrapper
{
    printf("output:\n");
    print_aes_block_in_hex(output);
    printf("\n");
}

void print_aes_data(byte *key, byte *input, byte *output) // "print_aes_block_in_hex()"-wrapper for printing of aes data
{
    printf("\n");
    print_aes_key(key);
    print_aes_input(input);
    print_aes_output(output);
    printf("\n");
}

int main()
{
    Aes aes_enc; // "(wolfcrypt) Aes"-data-structure for storing an aes encryption key
    Aes aes_dec; // "(wolfcrypt) Aes"-data-structure for storing an aes decryption key
    byte key[AES_128_KEY_SIZE] =
        {0x2b, 0x7e, 0x15, 0x16,
         0x28, 0xae, 0xd2, 0xa6,
         0xab, 0xf7, 0x15, 0x88,
         0x09, 0xcf, 0x4f, 0x3c}; // 128 bit aes key as a 16 ("AES_128_KEY_SIZE") byte array

    aes128_load_key(key); // setting up 128 bit aes key for hardware accelerated encryption and decryption

    wc_AesSetKeyDirect(&aes_enc,
                       key,
                       AES_128_KEY_SIZE,
                       NULL,
                       AES_ENCRYPTION); // storing "key" as a wolfcrypt aes encryption key in "aes_enc"

    wc_AesSetKeyDirect(&aes_dec,
                       key,
                       AES_128_KEY_SIZE,
                       NULL,
                       AES_DECRYPTION); // storing "key" as a wolfcrypt aes decryption key in "aes_dec"

    byte input[AES_BLOCK_SIZE] =
        {0x32, 0x43, 0xf6, 0xa8,
         0x88, 0x5a, 0x30, 0x8d,
         0x31, 0x31, 0x98, 0xa2,
         0xe0, 0x37, 0x07, 0x34}; // plain text
    byte output_enc[AES_BLOCK_SIZE] =
        {0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00}; // normalise "output_enc" (cipher) bytes with 0 respectively ASCII-nul
    byte output_dec[AES_BLOCK_SIZE] =
        {0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00}; // normalise "output_dec" (decrypted cipher) bytes with 0 respectively ASCII-nul

    clock_t t;                                            // clock structure for measuering time
    double time_taken_aes_enc_call_loop_in_sec;           // time measured for the execution of the "wc_AesEncryptDirect()-loop"
    double time_taken_for_one_aes_enc_call_in_ms;         // time calculated for the average execution of "wc_AesEncryptDirect()"
    double time_taken_aes_dec_call_loop_in_sec;           // time measured for the execution of the "wc_AesDecryptDirect()-loop"
    double time_taken_for_one_aes_dec_call_in_ms;         // time calculated for the average execution of "wc_AesDecryptDirect()"
    double enc_call_loop_mbytes_processed_per_sec;        // average data throughput of "wc_AesEncryptDirect()" in MB/s
    double dec_call_loop_mbytes_processed_per_sec;        // average data throughput of "wc_AesDecryptDirect()" in MB/s
    double time_taken_aes_enc_hw_acc_call_loop_in_sec;    // time measured for the execution of the "aes128_enc()-loop"
    double time_taken_for_one_aes_enc_hw_acc_call_in_ms;  // time calculated for the average execution of "aes128_enc()"
    double time_taken_aes_dec_hw_acc_call_loop_in_sec;    // time measured for the execution of the "aes128_dec()-loop"
    double time_taken_for_one_aes_dec_hw_acc_call_in_ms;  // time calculated for the average execution of "aes128_dec()"
    double enc_hw_acc_call_loop_mbytes_processed_per_sec; // average data throughput of "aes128_enc()" in MB/s
    double dec_hw_acc_call_loop_mbytes_processed_per_sec; // average data throughput of "aes128_dec()" in MB/s
    int bytes_processed = AES_BLOCK_SIZE * LOOP_CYCLES;   // bytes processed by the "wc_AesEncryptDirect() and wc_AesDecryptDirect loops"

    printf("\nInitialization successful!\n");
    printf("\nEncrypting...\n");

    /* encrypting the plain text "input" with the aes key "aes_enc" and saving the cipher in "output_enc" */
    wc_AesEncryptDirect(&aes_enc, output_enc, input);

    printf("\nEncryption successful!\n");
    printf("\nEncryption data:\n");
    print_aes_data(key, input, output_enc);

    printf("\nEncrypting with hardware acceleration...\n");

    /*
        encrypting with hardware acceleration
        the plain text "input"
        with the loaded aes key (aes128_load_key(key))
        and saving the cipher in "output_enc"
    */
    aes128_enc(input, output_enc);

    printf("\nEncryption with hardware accelerated code successful!\n");
    printf("\nEncryption with hardware acceleration data:\n");
    print_aes_data(key, input, output_enc);

    printf("\nDecrypting...\n");

    /* decrypting the cipher "output_enc" with the aes key "aes_dec" and saving the plain text in "output_dec" */
    wc_AesDecryptDirect(&aes_dec, output_dec, output_enc); // "output_dec" should be the same as "input"

    printf("\nDecryption successful!\n");
    printf("\nDecryption data:\n");
    print_aes_data(key, output_enc, output_dec); // "output_dec" should be the same as "input"

    printf("\nDecrypting with hardware acceleration...\n");

    /*
        decrypting with hardware acceleration
        the cipher "output_enc"
        with the loaded aes key (aes128_load_key(key))
        and saving the plain text in "output_dec"
    */
    aes128_enc(input, output_enc);

    printf("\nEncryption with hardware accelerated code successful!\n");
    printf("\nEncryption with hardware acceleration data:\n");
    print_aes_data(key, input, output_enc);

    printf("\nMeasuring performance...\n");

    t = clock(); // start measuering time taken by "wc_AesEncryptDirect()-loop"

    for (int i = 0; i < LOOP_CYCLES; i++) // "wc_AesEncryptDirect()-loop"
    {
        wc_AesEncryptDirect(&aes_enc, output_enc, input);
    }

    t = clock() - t; // stop measuering time taken by "wc_AesEncryptDirect()-loop"
    time_taken_aes_enc_call_loop_in_sec = ((double)t) / CLOCKS_PER_SEC;
    time_taken_for_one_aes_enc_call_in_ms = (time_taken_aes_enc_call_loop_in_sec / LOOP_CYCLES) * 1000;
    enc_call_loop_mbytes_processed_per_sec = (((double)bytes_processed) / 1000000) / time_taken_aes_enc_call_loop_in_sec;

    t = clock(); // start measuering time taken by "wc_AesDecryptDirect()-loop"

    for (int i = 0; i < LOOP_CYCLES; i++) // "wc_AesDecryptDirect()-loop"
    {
        wc_AesDecryptDirect(&aes_dec, output_dec, output_enc);
    }

    t = clock() - t; // stop measuering time taken by "wc_AesDecryptDirect()-loop"
    time_taken_aes_dec_call_loop_in_sec = ((double)t) / CLOCKS_PER_SEC;
    time_taken_for_one_aes_dec_call_in_ms = (time_taken_aes_dec_call_loop_in_sec / LOOP_CYCLES) * 1000;
    dec_call_loop_mbytes_processed_per_sec = (((double)bytes_processed) / 1000000) / time_taken_aes_dec_call_loop_in_sec;

    t = clock(); // start measuering time taken by "aes128_enc()-loop"

    for (int i = 0; i < LOOP_CYCLES; i++)
    {
        aes128_enc(input, output_enc);
    }

    t = clock() - t; // stop measuering time taken by "aes128_enc()-loop"
    time_taken_aes_enc_hw_acc_call_loop_in_sec = ((double)t) / CLOCKS_PER_SEC;
    time_taken_for_one_aes_enc_hw_acc_call_in_ms = (time_taken_aes_enc_hw_acc_call_loop_in_sec / LOOP_CYCLES) * 1000;
    enc_hw_acc_call_loop_mbytes_processed_per_sec =
        (((double)bytes_processed) / 1000000) / time_taken_aes_enc_hw_acc_call_loop_in_sec;

    t = clock(); // start measuering time taken by "aes128_dec()-loop"

    for (int i = 0; i < LOOP_CYCLES; i++)
    {
        aes128_dec(output_enc, output_dec);
    }

    t = clock() - t; // stop measuering time taken by "aes128_dec()-loop"
    time_taken_aes_dec_hw_acc_call_loop_in_sec = ((double)t) / CLOCKS_PER_SEC;
    time_taken_for_one_aes_dec_hw_acc_call_in_ms = (time_taken_aes_dec_hw_acc_call_loop_in_sec / LOOP_CYCLES) * 1000;
    dec_hw_acc_call_loop_mbytes_processed_per_sec =
        (((double)bytes_processed) / 1000000) / time_taken_aes_dec_hw_acc_call_loop_in_sec;

    printf("\n--------------------------------------------------------------------------------\n");
    printf("\nThe execution of a wc_AesEncryptDirect() call takes about %f ms.\n",
           time_taken_for_one_aes_enc_call_in_ms);
    printf("\nThe execution of %i wc_AesEncryptDirect() calls took about %f seconds.\n",
           LOOP_CYCLES,
           time_taken_aes_enc_call_loop_in_sec);
    printf("\nwc_AesEncryptDirect() processed %i bytes of input data in %f seconds.\n",
           bytes_processed,
           time_taken_aes_enc_call_loop_in_sec);
    printf("\nwc_AesEncryptDirect() has a data throughput of %f MB/s.\n",
           enc_call_loop_mbytes_processed_per_sec);
    printf("\n--------------------------------------------------------------------------------\n");
    printf("\nThe execution of a aes128_enc() (hardware accelerated code) call takes about %f ms.\n",
           time_taken_for_one_aes_enc_hw_acc_call_in_ms);
    printf("\nThe execution of %i aes128_enc() (hardware accelerated code) calls took about %f seconds.\n",
           LOOP_CYCLES,
           time_taken_aes_enc_hw_acc_call_loop_in_sec);
    printf("\naes128_enc() (hardware accelerated code) processed %i bytes of input data in %f seconds.\n",
           bytes_processed,
           time_taken_aes_enc_hw_acc_call_loop_in_sec);
    printf("\naes128_enc() (hardware accelerated code) has a data throughput of %f MB/s.\n",
           enc_hw_acc_call_loop_mbytes_processed_per_sec);
    printf("\n--------------------------------------------------------------------------------\n");
    printf("\nThe execution of a wc_AesDecryptDirect() call takes about %f ms.\n",
           time_taken_for_one_aes_dec_call_in_ms);
    printf("\nThe execution of %i wc_AesDecryptDirect() calls took about %f seconds.\n",
           LOOP_CYCLES,
           time_taken_aes_dec_call_loop_in_sec);
    printf("\nwc_AesDecryptDirect() processed %i bytes of input data in %f seconds.\n",
           bytes_processed,
           time_taken_aes_dec_call_loop_in_sec);
    printf("\nwc_AesDecryptDirect() has a data throughput of %f MB/s.\n",
           dec_call_loop_mbytes_processed_per_sec);
    printf("\n--------------------------------------------------------------------------------\n");
    printf("\nThe execution of a aes128_dec() (hardware accelerated code) call takes about %f ms.\n",
           time_taken_for_one_aes_dec_hw_acc_call_in_ms);
    printf("\nThe execution of %i aes128_dec() (hardware accelerated code) calls took about %f seconds.\n",
           LOOP_CYCLES,
           time_taken_aes_dec_hw_acc_call_loop_in_sec);
    printf("\naes128_dec() (hardware accelerated code) processed %i bytes of input data in %f seconds.\n",
           bytes_processed,
           time_taken_aes_dec_hw_acc_call_loop_in_sec);
    printf("\naes128_dec() (hardware accelerated code) has a data throughput of %f MB/s.\n",
           dec_hw_acc_call_loop_mbytes_processed_per_sec);
    printf("\n--------------------------------------------------------------------------------\n\n");

    return 0;
}