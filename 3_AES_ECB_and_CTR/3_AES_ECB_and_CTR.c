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
    $gcc 3_AES_ECB_and_CTR.c -o exe -lm -lwolfssl

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

    MESSAGE_SIZE:

    3_AES_CTR_plain.bmp is 2 359 350 Bytes.
    => 2 359 350 / 16 == 147 459.375
    => 16 * 147 460 == 2359360
    => MESSAGE_SIZE = 2359360

    --------------------------------------------------------------------------------

    relevant output:

    first randomly generated aes key:

    60 05 eb de 
    ee ad 59 34 
    2e d8 b7 04 
    d1 63 ab 09

    --------------------------------------------------------------------------------

    AES ECB method observations:

    encrypting without "salting" leads to recognizable patterns.
    Such phenomena occur particularly with symmetric encryption methods.
    AES will always generate the same cipher,
    if the input (plain text) is always the same
    and the key is always the same.

    For instance:

    AES 128 bit key:
    60 05 eb de 
    ee ad 59 34 
    2e d8 b7 04 
    d1 63 ab 09

    Input data (plain text):
    00 00 00 00 
    00 00 00 00 
    00 00 00 00 
    00 00 00 00 

    Output data (cipher respectively encrypted input data):
    90 93 91 25 
    03 82 3a 6b 
    3c 13 52 a5 
    48 51 26 55
    
    This behaviour leads to recognizable patterns,
    since repeating 128 bit patterns (16 byte aes blocks) in the cipher
    indicates repeating 128 bit patterns in the input respectively plain text.
    (If the output data is always the same,
    the input data has to be also always the same.)
    Furthermore, encryption without noise
    only leads to the same modification 
    of the input bit patterns,
    easily visible in images especially to the eye.

    --------------------------------------------------------------------------------

    AES CTR method observations:

    "Salting" the encryption creates noise in the cipher.
    In this example, "salting" is done using an initialization vector.
    The initialization vector is first iterated,
    then aes encrypted with a key
    and finally "xored" with the data to be encrypted (input or plain text).
    All 16-byte AES blocks of the input
    are encrypted using a "unique" modification (xored with a "unique" 128 bit pattern),
    which leads to unrecognizable patterns respectively noise in the cipher.

    --------------------------------------------------------------------------------

    scenario:

    - 3_AES_CTR_plain_2.bmp       (not known)
    - 3_AES_CTR_cipher_CTR_2.bmp  (known)
    - 3_AES_CTR_plain.bmp         (known)
    - 3_AES_CTR_cipher_CTR.bmp    (known)
    - same AES key and iv is used

    As far as is publicly known, there is no way to do 
    a "Known-plaintext attack" on AES.
    (source: https://crypto.stackexchange.com/questions/3952/is-it-possible-to-obtain-aes-128-key-from-a-known-ciphertext-plaintext-pair)

    Even in the given scenario,
    it is extremly hard to make conclusions,
    since the encryption is "salted"
    and the cipher has noise (CTR).
    But maybe it could help by a brute force attack.

    There is no known way to decrypt the "3_AES_CTR_cipher_CTR_2" cipher
    and there is no known way to obtain the key.
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define WOLFSSL_AES_DIRECT

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/aes.h>

#define MESSAGE_SIZE 2359360 // look at line 68

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

void print_n_aes_blocks_in_hex(int n, byte *data) // printing "n" aes blocks of the "data"-byte-array in hex
{
    for (int i = 0; i < (n * AES_BLOCK_SIZE); i++)
    {
        printf("%02x ", data[i]);

        if ((((i + 1) % 4) == 0))
        {
            printf("\n");
        }
    }
}

void print_random_aes_key() // printing a randomly generated 128 bit (16 bytes) aes key in hex
{
    WC_RNG rng;
    wc_InitRng(&rng);
    byte aes_key[AES_128_KEY_SIZE];
    wc_RNG_GenerateBlock(&rng, aes_key, sizeof aes_key);

    print_aes_block_in_hex(aes_key);
}

void print_aes_encrypted_zeros()
{
    Aes aes_enc; // "(wolfcrypt) Aes"-data-structure for storing an aes encryption key
    byte aes_key[AES_128_KEY_SIZE] = {
        0x60, 0x05, 0xbe, 0xed,
        0xee, 0xad, 0x59, 0x34,
        0x2e, 0xd8, 0x7b, 0x04,
        0xd1, 0x63, 0xab, 0x90}; // a by "print_random_aes_key()" generated 128 bit aes key

    wc_AesSetKeyDirect(&aes_enc, aes_key, sizeof aes_key, NULL, AES_ENCRYPTION); // storing "aes_key" as a wolfcrypt aes encryption key in "aes_enc"

    byte aes_plain[AES_BLOCK_SIZE] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00}; // plain text with length of AES_BLOCK_SIZE - data is just 16 bytes of 0

    static uint8_t aes_cipher[AES_BLOCK_SIZE]; // cipher with length of AES_BLOCK_SIZE

    wc_AesEncryptDirect(&aes_enc, aes_cipher, aes_plain);

    printf("\n\nAES 128 bit key:\n\n");
    print_aes_block_in_hex(aes_key);
    printf("\n\nInput data (plain text):\n\n");
    print_aes_block_in_hex(aes_plain);
    printf("\n\nOutput data (cipher respectively encrypted input data):\n\n");
    print_aes_block_in_hex(aes_cipher);
    printf("\n\n");
}

void doAesEcb() // generate a valid "3_AES_CTR_cipher_ECB.bmp" file with AES ECB encrypted "3_AES_CTR_plain.bmp" data
{
    Aes aes_enc; // "(wolfcrypt) Aes"-data-structure for storing an aes encryption key
    byte aes_key[AES_128_KEY_SIZE] = {
        0x60, 0x05, 0xbe, 0xed,
        0xee, 0xad, 0x59, 0x34,
        0x2e, 0xd8, 0x7b, 0x04,
        0xd1, 0x63, 0xab, 0x90}; // a by "print_random_aes_key()" generated 128 bit aes key

    wc_AesSetKeyDirect(&aes_enc, aes_key, sizeof aes_key, NULL, AES_ENCRYPTION); // storing "aes_key" as a wolfcrypt aes encryption key in "aes_enc"

    static uint8_t aes_plain[MESSAGE_SIZE];       // plain text with length of MESSAGE_SIZE
    FILE *f = fopen("3_AES_CTR_plain.bmp", "rb"); // reading "3_AES_CTR_plain.bmp" bitmap file
    fread(aes_plain, 1, MESSAGE_SIZE, f);         // copying "3_AES_CTR_plain.bmp" data to "aes_plain"
    fclose(f);                                    // closing "3_AES_CTR_plain.bmp" bitmap file

    static uint8_t aes_cipher[MESSAGE_SIZE]; // cipher with length of MESSAGE_SIZE

    /* encrypting the plain text "aes_plain" with the aes key "aes_enc" and saving the cipher in "aes_cipher" */
    for (int i = 0; i < MESSAGE_SIZE; i += AES_BLOCK_SIZE)
    {
        wc_AesEncryptDirect(&aes_enc, aes_cipher + i, aes_plain + i);
    }

    /* 
        restoring first 54 bytes (bitmap header)
        of "3_AES_CTR_plain.bmp" respectively "aes_plain"
        in "aes_cipher" -> valid .bmp data)
    */
    memcpy(aes_cipher, aes_plain, 54);

    FILE *fp = fopen("3_AES_CTR_cipher_ECB.bmp", "w+");          // opening "3_AES_CTR_cipher_ECB.bmp" bitmap file for writing
    fwrite(aes_cipher, sizeof(uint8_t), sizeof(aes_cipher), fp); // writing the cipher "aes_cipher" to "3_AES_CTR_cipher_ECB.bmp"
    fclose(fp);                                                  // closing "3_AES_CTR_plain.bmp" bitmap file
}

void doAesCtr() // generate a valid "3_AES_CTR_cipher_CTR.bmp" file with AES CTR encrypted "3_AES_CTR_plain.bmp" data
{
    Aes aes_enc; // "(wolfcrypt) Aes"-data-structure for storing an aes encryption key
    byte aes_key[AES_128_KEY_SIZE] = {
        0x60, 0x05, 0xbe, 0xed,
        0xee, 0xad, 0x59, 0x34,
        0x2e, 0xd8, 0x7b, 0x04,
        0xd1, 0x63, 0xab, 0x90}; // a by "print_random_aes_key()" generated 128 bit aes key

    static uint64_t aes_enc_iv[2] = {123456, 0}; // initialization vector

    wc_AesSetKeyDirect(&aes_enc, aes_key, sizeof aes_key, NULL, AES_ENCRYPTION);

    static uint8_t aes_plain[MESSAGE_SIZE];       // plain text with length of MESSAGE_SIZE
    FILE *f = fopen("3_AES_CTR_plain.bmp", "rb"); // reading "3_AES_CTR_plain.bmp" bitmap file
    fread(aes_plain, 1, MESSAGE_SIZE, f);         // copying "3_AES_CTR_plain.bmp" data to "aes_plain"
    fclose(f);                                    // closing "3_AES_CTR_plain.bmp" bitmap file

    static uint8_t aes_cipher[MESSAGE_SIZE]; // cipher with length of MESSAGE_SIZE

    /*
        encrypting the plain text "aes_plain"
        with the aes key "aes_enc"
        and the initialization vector "aes_enc_iv"
        and saving the cipher in "aes_cipher"
    */

    for (int i = 0; i < MESSAGE_SIZE; i += AES_BLOCK_SIZE)
    {
        static uint8_t aes_xor[AES_BLOCK_SIZE];
        wc_AesEncryptDirect(&aes_enc, aes_xor, (byte *)aes_enc_iv); // generating "salt"

        for (int j = 0; j < AES_BLOCK_SIZE; ++j) // encrypting the actuall data
        {
            aes_cipher[i + j] = aes_plain[i + j] ^ aes_xor[j]; // encrypting by xoring the plain text with the "salt" "aes_xor"
        }

        aes_enc_iv[1]++; // incrementing the initialization vector "aes_enc_iv" to generate noise in "aes_cipher"
    }

    /* 
        restoring first 54 bytes (bitmap header)
        of "3_AES_CTR_plain.bmp" respectively "aes_plain"
        in "aes_cipher" -> valid .bmp data)
    */
    memcpy(aes_cipher, aes_plain, 54);

    FILE *fp = fopen("3_AES_CTR_cipher_CTR.bmp", "w+");          // opening "3_AES_CTR_cipher_CTR.bmp" bitmap file for writing
    fwrite(aes_cipher, sizeof(uint8_t), sizeof(aes_cipher), fp); // writing the cipher "aes_cipher" to "3_AES_CTR_cipher_CTR.bmp"
    fclose(fp);                                                  // closing "3_AES_CTR_plain.bmp" bitmap file
}

int main()
{
    print_aes_encrypted_zeros();
    doAesEcb();
    doAesCtr();
    return 0;
}