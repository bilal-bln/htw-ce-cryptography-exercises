/*
    references:

    https://wolfssl.com/doxygen/wolfssl_2wolfcrypt_2pwdbased_8h.html
    https://wolfssl.com/doxygen/group__Password.html#ga744b805fda60c99a590ce7d6896e836a
    https://en.wikipedia.org/wiki/Rainbow_table
    https://en.wikipedia.org/wiki/HMAC
    https://en.wikipedia.org/wiki/PBKDF2

    --------------------------------------------------------------------------------

    build wolfCrypt (and wolfSSL) on Ubuntu 18.04 (x86 PC)
    with RSA and key generation enabled (DISABLED by default):

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-pwdbased
    make
    sudo make install

    sudo ldconfig

    --------------------------------------------------------------------------------

    build this code on Ubuntu 18.04 (x86 PC) with:
    $gcc HMAC_and_PBKDF.c -o exe -lm -lwolfssl

    then run the executable on Ubuntu 18.04 (x86 PC) with:
    $LD_LIBRARY_PATH=/usr/local/lib ./exe

    --------------------------------------------------------------------------------

    relevant output:

    psk: 123456
    ssid: FRITZ!Box Gastzugang
    iterations: 4096
    wc_PBKDF2-return-value: 0 - SUCCESS!

    PMK (hex output): 
    9946868b85dd89d032cd7530b1c1a537a5c294161da51da7bfe5e9637b82eea64

    PMK (formatted hex output): 
    99 46 86 8b 
    5d d8 9d 03 
    2c d7 53 0b 
    1c 1a 53 7a 
    5c 29 41 61 
    da 51 da 7b 
    fe 5e 96 37 
    b8 2e ea 64 

*/

#include <stdio.h>

#include <wolfssl/options.h>        // prevents compiling and runtime errors - include always first
#include <wolfssl/wolfcrypt/hmac.h> // MD5 constant
#include <wolfssl/wolfcrypt/pwdbased.h>

/* 
    printing the "data"-byte-array
    with a length of "length_of_byte_array"
    in hex
*/
void print_byte_array_in_hex(int length_of_byte_array, byte *data)
{
    for (int i = 0; i < length_of_byte_array; i++)
    {
        printf("%02x", data[i]);
    }
}

/* 
    printing the "data"-byte-array
    with a length of "length_of_byte_array"
    in formatted hex
*/
void print_byte_array_in_formatted_hex(int length_of_byte_array, byte *data)
{
    for (int i = 0; i < length_of_byte_array; i++)
    {
        printf("%02x ", data[i]);

        if ((((i + 1) % 4) == 0))
        {
            printf("\n");
        }
    }
}

int main()
{
    byte psk[] = "123456";                // matriculation number
    byte ssid[] = "FRITZ!Box Gastzugang"; // ESSID
    int iterations = 4096;                // constant
    byte pmk[32];                         // output
    int ret;                              // wc_PBKDF2-return-value

    ret = wc_PBKDF2(
        pmk,
        psk,
        sizeof(psk),
        ssid,
        sizeof(ssid),
        iterations,
        sizeof(pmk),
        SHA256);

    if (ret == 0)
    {
        printf("\n\n\n");
        printf("psk: %s\n", psk);
        printf("ssid: %s\n", ssid);
        printf("iterations: %i\n", iterations);
        printf("wc_PBKDF2-return-value: %i - SUCCESS!\n\n", ret);
        printf("PMK (hex output): \n");
        print_byte_array_in_hex(sizeof(pmk), pmk);
        printf("\n\nPMK (formatted hex output): \n");
        print_byte_array_in_formatted_hex(sizeof(pmk), pmk);
        printf("\n\n\n");
    }
    else
    {
        printf("\n\n\nError!\n\n\n");
    }

    return 0;
}