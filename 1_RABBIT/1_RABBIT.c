/*
    references:

    https://github.com/wolfSSL/wolfssl/wiki/Building-wolfSSL
    https://github.com/wolfSSL/wolfssl/blob/master/wrapper/python/wolfcrypt/README.rst
    https://www.wolfssl.com/docs/wolfssl-manual/ch10/
    https://en.wikipedia.org/wiki/ASCII

    --------------------------------------------------------------------------------

    build wolfCrypt (and wolfSSL) on Ubuntu 18.04 with RABBIT enabled (disabled by default):

    sudo apt-get update
    sudo apt-get install -y git autoconf libtool

    git clone https://github.com/wolfssl/wolfssl.git
    cd wolfssl/
    ./autogen.sh
    ./configure --enable-rabbit
    make
    sudo make install

    sudo ldconfig

    --------------------------------------------------------------------------------

    build this code on Ubuntu 18.04 with:
    $gcc 1_RABBIT.c -o exe -lm -lwolfssl

    then run the executable on Ubuntu 18.04 with:
    $LD_LIBRARY_PATH=/usr/local/lib ./exe

    --------------------------------------------------------------------------------

    relevant output:
    
    ##############################

    Printing decrypted messages with more then 3 characters...

    ------------------------------

    pin:               2020
    decrypted message: Yosemite National Park

    ##############################
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfssl/options.h> // prevents compiling and runtime errors - include always first
// #include <wolfssl/ssl.h>  // if necessary uncomment - could prevent compiling and runtime errors
#include <wolfssl/wolfcrypt/rabbit.h>
#include <wolfssl/wolfcrypt/coding.h>

#define MIN_PIN 1
#define MAX_PIN 9999
#define KEY_LENGTH 16
#define MSG_LENGTH 100

void print_key_and_msg(byte *key, byte *msg)
{
    printf("------------------------------\n");
    printf("\n");
    printf("pin:               %s\n", key);
    printf("decrypted message: %s\n", msg);
    printf("\n");
}

int main()
{

    printf("\nProgram starting...\n");

    if (wolfCrypt_Init() != 0)
    {
        printf("Error with wolfCrypt_Init call\n");
        return -1;
    }

    Rabbit dec;
    byte key[KEY_LENGTH] = {0, 0, 0, 0,
                            0, 0, 0, 0,
                            0, 0, 0, 0,
                            0, 0, 0, 0}; // normalise "key" bytes with 0 respectively ASCII-nul

    byte secret_base64[34] = "HfDr2ZhjsPtqCg8BdmQCQOaSNo7E3+Y=";
    byte secret[25];
    int secretlen = sizeof(secret);
    Base64_Decode(secret_base64, sizeof(secret_base64), secret, &secretlen);

    byte msg[MSG_LENGTH]; // decrypted message
    int success = 0;      // validation flag of "msg"

    byte long_msgs_keys[MAX_PIN][KEY_LENGTH]; // memory for passwords of long valid decrypted messages
    byte long_msgs[MAX_PIN][MSG_LENGTH];      // memory for long valid decrypted messages
    int amount_of_long_msgs = 0;              // amount of long valid decrypted messages with the offset 0

    printf("Initialization successful!\n");
    printf("Brute forcing...\n");
    printf("\n");

    for (int pin = 0; pin <= MAX_PIN; pin++)
    {
        sprintf(key, "%04i", pin); // last 12 bytes of "key" are 0 respectively ASCII-nul

        wc_RabbitSetKey(&dec, key, NULL);                    // "initialization vector" respectively "iv" is NULL
        wc_RabbitProcess(&dec, msg, secret, sizeof(secret)); // decrypt the cipher "secret"

        for (int i = 0; i < sizeof(msg); i++) // check if characters of "msg" are valid
        {
            if (isalpha(msg[i]) || isdigit(msg[i]) || isspace(msg[i])) // check if character is valid
            {
                success = 1;
            }
            else
            {
                if (msg[i] == '\0') // if end of string is reached (and "i" is greater then 0), validation is successful
                {
                    if (i > 3) // if "i" is greater then 3, "msg" is a long valid decrypted message and is saved in memory
                    {
                        /*
                            the first "4" characters of "key"
                            are saved in the "long_msgs_keys"-byte-array
                            with the index "amount_of_long_msgs"
                        */
                        strncpy(long_msgs_keys[amount_of_long_msgs],
                                key,
                                4);

                        /*
                            the fifth byte (or the byte with the index "4")
                            of "long_msgs_keys"-byte-array
                            with the index "amount_of_long_msgs"
                            is 0 respectively ASCII-nul
                        */
                        long_msgs_keys[amount_of_long_msgs][4] = 0;

                        /*
                            "msg"-string is saved in the "long_msgs"-byte-array
                            with the index "amount_of_long_msgs".
                            "i" is the length of "msg"-string
                            and can not be longer then "MSG_LENGTH"
                        */
                        strncpy(long_msgs[amount_of_long_msgs],
                                msg,
                                i); //

                        /*
                            the byte with the index "i" (the length of "msg"-string)
                            of "long_msgs"-byte-array
                            with the index "amount_of_long_msgs"
                            is 0 respectively ASCII-nul
                        */
                        long_msgs_keys[amount_of_long_msgs][i] = 0;

                        amount_of_long_msgs++; // increment amount of long valid decrypted messages
                    }

                    i = sizeof(msg); // break out of the loop
                }
                else // character is invalid, the validation fails ("success" = 0;) and the loop is interrupted
                {
                    success = 0;     // validation failed
                    i = sizeof(msg); // break out of the loop
                }
            }
        }

        if (success == 1) // if the validation did not fail
        {
            print_key_and_msg(key, msg); // print the pin respectively "key" and the decrypted message respectively "msg"
        }
    }

    printf("##############################\n");
    printf("\n");
    printf("Printing decrypted messages with more then 3 characters...\n");
    printf("\n");

    for (int i = 0; i < amount_of_long_msgs; i++) // print all long valid decrypted messages and their pins
    {
        print_key_and_msg(long_msgs_keys[i], long_msgs[i]);
    }

    printf("##############################\n");
    printf("\n");
    printf("Program terminated...\n");
    printf("\n");

    return 0;
}