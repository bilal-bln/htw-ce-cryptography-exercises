/*
    references:

    https://github.com/wolfSSL/wolfssl/wiki/Building-wolfSSL
    https://github.com/wolfSSL/wolfssl/blob/master/wrapper/python/wolfcrypt/README.rst

    --------------------------------------------------------------------------------

    build wolfCrypt (and wolfSSL) on Ubuntu 18.04 with:

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure
    make
    sudo make install

    sudo ldconfig

    --------------------------------------------------------------------------------

    build this code on Ubuntu 18.04 with:
    $gcc 0_Hello_wolfcrypt.c -o exe -lm -lwolfssl

    then run the executable on Ubuntu 18.04 with:
    $LD_LIBRARY_PATH=/usr/local/lib ./exe

    --------------------------------------------------------------------------------

    relevant output:
    
    Hello Wolf!
    83524a9260271e7c42df5bf43024d12f08e7f1ec53c5c8eb2623783cfc847209
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/sha256.h>

int main()
{
    printf("\nHello Wolf!\n");

    if (wolfCrypt_Init() != 0)
    {
        printf("Error with wolfCrypt_Init call\n");
        return -1;
    }

    byte hash[WC_SHA256_DIGEST_SIZE];

    wc_Sha256 sha256;

    wc_InitSha256(&sha256);
    wc_Sha256Update(&sha256, "123456", 6);
    wc_Sha256Final(&sha256, hash);

    for (int i = 0; i < sizeof(hash); i++)
    {
        printf("%02x", hash[i]);
    }

    printf("\n\n");

    return 0;
}