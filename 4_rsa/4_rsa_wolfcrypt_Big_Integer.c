/*
    references:

    https://www.wolfssl.com/docs/wolfssl-manual/ch7/
    https://www.wolfssl.com/docs/wolfssl-manual/ch10/
    https://www.wolfssl.com/forums/topic817-wcinitrsakey-causes-stack-smashing.html
    https://www.wolfssl.com/forums/topic738-rsa-key-generation-from-a-pass-phrase.html

    --------------------------------------------------------------------------------

    build wolfCrypt (and wolfSSL) on Ubuntu 18.04 (x86 PC)
    with RSA and key generation enabled (DISABLED by default):

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-rsa
    ./configure --enable-keygen
    make
    sudo make install

    sudo ldconfig

    --------------------------------------------------------------------------------

    build this code on Ubuntu 18.04 (x86 PC) with:
    $gcc 4_rsa_wolfcrypt_Big_Integer.c -o exe -lm -lwolfssl

    then run the executable on Ubuntu 18.04 (x86 PC) with:
    $LD_LIBRARY_PATH=/usr/local/lib ./exe

    --------------------------------------------------------------------------------

    relevant output:

    p = 0xCAE89DB69765AB8E315419F2E0CC1F33D5D0A15C61D9F04CEBF776ABD6EE0CCF
    q = 0xB8688AF7FDD8F8820520A8C66C781054E1004025CC00C6B1607273E749B1D379
    n = 0x922A0E0143A70A7FB374493FE6179EA01F61356A873FA4E306550DE26B7D07D1C4E0A8A65C043218DDDDB9B640708379F87DBBCE01C3E852C09CC165AD31AAD7
    e = 0x010001
    d = 0x373DBFB7489B5C43714E74D4BAA098AA09D2127F2588AF47C23FE91476ED75438753B5D8AE7E41B5119881288EBB652A5C58F8D409CE2B7FB0BEFA23EF4EB691
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define WOLFSSL_KEY_GEN

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/rsa.h>

#define LOOP_CYCLES 100

int main()
{
    printf("\n\n----------------------------------------\n");
    printf("\nStarting programm...\n");

    if (wolfCrypt_Init() != 0)
    {
        printf("Error with wolfCrypt_Init call\n");
        return -1;
    }

    printf("\nWolfCrypt initialization successful!\n");

    printf("\nInitializing...\n");

    RsaKey rsaPrivKey;
    WC_RNG rng;
    long e = 65537; // "e" is the exponent - 65537 is the standard value to use for an exponent

    printf("\nInitialization successful!\n");

    wc_InitRsaKey(&rsaPrivKey, 0); // not using heap hint. No custom memory

    printf("\nRSA private key initialization successful!\n");

    wc_InitRng(&rng);

    printf("\nRNG initialization successful!\n");

    if (wc_MakeRsaKey(&rsaPrivKey, RSA_MIN_SIZE, e, &rng) != 0) // generate 512 bit long private key
    {
        printf("Error with wc_MakeRsaKey call\n"); // if generation fails
    }

    printf("\nRSA private key generation successful!\n\n");

    /*
        Printing RSA Parameter.
        if necessary
        #include <wolfssl/wolfcrypt/wolfmath.h>
        for "wc_export_int()"
    */

    byte buffer[RSA_MIN_SIZE];
    uint32_t bufferLen = sizeof buffer;

    wc_export_int(&rsaPrivKey.p, buffer, &bufferLen, RSA_MIN_SIZE, WC_TYPE_HEX_STR);
    printf("p = 0x%s\n", buffer);
    wc_export_int(&rsaPrivKey.q, buffer, &bufferLen, RSA_MIN_SIZE, WC_TYPE_HEX_STR);
    printf("q = 0x%s\n", buffer);
    wc_export_int(&rsaPrivKey.n, buffer, &bufferLen, RSA_MIN_SIZE, WC_TYPE_HEX_STR);
    printf("n = 0x%s\n", buffer);
    wc_export_int(&rsaPrivKey.e, buffer, &bufferLen, RSA_MIN_SIZE, WC_TYPE_HEX_STR);
    printf("e = 0x%s\n", buffer);
    wc_export_int(&rsaPrivKey.d, buffer, &bufferLen, RSA_MIN_SIZE, WC_TYPE_HEX_STR);
    printf("d = 0x%s\n", buffer);

    /* - BONUS task ----------------------------------------------------------------- */

    printf("\nMeasuring RSA performance...\n\n");

    printf("RSA_MIN_SIZE: %i\n", RSA_MIN_SIZE);
    printf("RSA_MIN_SIZE: %i\n\n", RSA_MAX_SIZE);

    for (int rsa_key_size = RSA_MIN_SIZE; rsa_key_size <= RSA_MAX_SIZE; rsa_key_size += 256)
    {
        clock_t t;
        double time_taken[LOOP_CYCLES];
        double total_time_taken = 0;
        double average_time_take = 0;
        double min_time_taken = 0;
        double max_time_taken = 0;

        for (int i = 0; i < LOOP_CYCLES; i++)
        {
            t = clock();

            /*
            RsaKey rsaPrivKeyPer;
            WC_RNG rngPer;
            long ePer = 65537;
            wc_InitRsaKey(&rsaPrivKeyPer, 0);
            wc_InitRng(&rngPer);
            wc_MakeRsaKey(&rsaPrivKeyPer, RSA_MIN_SIZE, ePer, &rngPer);
            */

            wc_MakeRsaKey(&rsaPrivKey, RSA_MIN_SIZE, e, &rng);
            t = clock() - t;
            time_taken[i] = ((double)t) / CLOCKS_PER_SEC;
        }

        min_time_taken = time_taken[0];
        max_time_taken = time_taken[0];

        for (int i = 0; i < LOOP_CYCLES; i++)
        {
            if (min_time_taken > time_taken[i])
            {
                min_time_taken = time_taken[i];
            }

            if (max_time_taken < time_taken[i])
            {
                max_time_taken = time_taken[i];
            }

            total_time_taken += time_taken[i];
        }

        average_time_take = total_time_taken / LOOP_CYCLES;

        printf("RSA %i bit key generation in %i loop cycles took\n", rsa_key_size, LOOP_CYCLES);
        printf("in average: %f seconds\n", (float)average_time_take);
        printf("in total:   %f seconds\n", (float)total_time_taken);
        printf("minimum:    %f seconds\n", (float)min_time_taken);
        printf("maximum:    %f seconds\n\n\n", (float)max_time_taken);
    }

    printf("----------------------------------------\n\n");

    return 0;
}