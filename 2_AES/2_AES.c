/*
    references:

    https://github.com/wolfSSL/wolfssl/wiki/Building-wolfSSL
    https://github.com/wolfSSL/wolfssl/blob/master/wrapper/python/wolfcrypt/README.rst
    https://csrc.nist.gov/publications/detail/fips/197/final
    https://en.wikipedia.org/wiki/AES_instruction_set
    https://stackoverflow.com/questions/3716691/relation-between-input-and-ciphertext-length-in-aes
    https://www.wolfssl.com/docs/wolfssl-manual/ch10/
    https://www.wolfssl.com/doxygen/group__AES.html

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
    $gcc 2_AES.c -o exe -lm -lwolfssl

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

    answers to questions of performance:

    A increasing key length (128 bit to 192 bit to 256 bit)
    should generally result in decreasing performance and increasing security.
    The (type of) data input (like bit pattern)
    should not have an impact on performance,
    as long as it is a 16 byte data block (AES_BLOCK_SIZE).
    Data input can only been processed in 16 byte data blocks.
    Of course a increasing number of data to process
    results in a increasing computing time.
    Decryption should take about as long as encryption,
    since the procedures are symmetrical (confirmed by tests). 

    --------------------------------------------------------------------------------

    relevant output:

    Encryption:

    key:
    2b 7e 15 16 
    28 ae d2 a6 
    ab f7 15 88 
    09 cf 4f 3c 

    input:
    32 43 f6 a8 
    88 5a 30 8d 
    31 31 98 a2 
    e0 37 07 34 

    output:
    39 25 84 1d 
    02 dc 09 fb 
    dc 11 85 97 
    19 6a 0b 32 
    
    Decryption:

    key:
    2b 7e 15 16 
    28 ae d2 a6 
    ab f7 15 88 
    09 cf 4f 3c 

    input:
    39 25 84 1d 
    02 dc 09 fb 
    dc 11 85 97 
    19 6a 0b 32 

    output:
    32 43 f6 a8 
    88 5a 30 8d 
    31 31 98 a2 
    e0 37 07 34 

    Measured performance:

    The execution of a wc_AesEncryptDirect() call takes about 0.000224 ms.
    The execution of 10000000 wc_AesEncryptDirect() calls took about 2.237189 seconds.
    wc_AesEncryptDirect() processed 160000000 bytes of input data in 2.237189 seconds.
    wc_AesEncryptDirect() has a data throughput of 71.518321 MB/s.

    The execution of a wc_AesDecryptDirect() call takes about 0.000218 ms.
    The execution of 10000000 wc_AesDecryptDirect() calls took about 2.181797 seconds.
    wc_AesDecryptDirect() processed 160000000 bytes of input data in 2.181797 seconds.
    wc_AesDecryptDirect() has a data throughput of 73.334045 MB/s.
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define WOLFSSL_AES_DIRECT

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/aes.h>

#define LOOP_CYCLES 10000000 // amount of "wc_AesEncryptDirect() and wc_AesDecryptDirect() loop" cycles

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

    clock_t t;                                          // clock structure for measuering time
    double time_taken_aes_enc_call_loop_in_sec;         // time measued for the execution of the "wc_AesEncryptDirect()-loop"
    double time_taken_for_one_aes_enc_call_in_ms;       // time calculated for the average execution of "wc_AesEncryptDirect()"
    double time_taken_aes_dec_call_loop_in_sec;         // time measued for the execution of the "wc_AesDecryptDirect()-loop"
    double time_taken_for_one_aes_dec_call_in_ms;       // time calculated for the average execution of "wc_AesDecryptDirect()"
    double enc_call_loop_mbytes_processed_per_sec;      // average data throughput of "wc_AesEncryptDirect()" in MB/s
    double dec_call_loop_mbytes_processed_per_sec;      // average data throughput of "wc_AesDecryptDirect()" in MB/s
    int bytes_processed = AES_BLOCK_SIZE * LOOP_CYCLES; // bytes processed by the "wc_AesEncryptDirect() and wc_AesDecryptDirect loops"

    printf("\nInitialization successful!\n");
    printf("\nEncrypting...\n");

    /* encrypting the plain text "input" with the aes key "aes_enc" and saving the cipher in "output_enc" */
    wc_AesEncryptDirect(&aes_enc, output_enc, input);

    printf("\nEncryption successful!\n");
    printf("\nEncryption data:\n");
    print_aes_data(key, input, output_enc);

    printf("\nDecrypting...\n");

    /* decrypting the cipher "output_enc" with the aes key "aes_dec" and saving the plain text in "output_dec" */
    wc_AesDecryptDirect(&aes_dec, output_dec, output_enc); // "output_dec" should be the same as "input"

    printf("\nDecryption successful!\n");
    printf("\nDecryption data:\n");
    print_aes_data(key, output_enc, output_dec); // "output_dec" should be the same as "input"

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
    printf("\n--------------------------------------------------------------------------------\n\n");

    return 0;
}