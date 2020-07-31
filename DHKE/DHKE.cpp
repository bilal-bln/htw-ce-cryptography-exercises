/*
    build this code on Ubuntu 18.04 (x86 PC) with:
    $g++ DHKE.cpp -o exe

    then run the executable on Ubuntu 18.04 (x86 PC) with:
    $./exe

    --------------------------------------------------------------------------------

    Answers:

    B is 3245.
    our secret (key) is 29287.
    a is 2020.

    --------------------------------------------------------------------------------

    relevant output:

    ####################

    p: 30011
    g: 2
    A: 1103
    b: 123456
    B: 3245
    our_secret: 29287

    Bruteforcing the secret a was successful!

    A_brutefore: 1103
    a: 2020

    ####################
*/

// RSA mini demo using int

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

// is p a prime?
int is_prime(int p)
{
    for (int t = 2; t * t <= p; t++)
    {
        if (p % t == 0)
            return 0;
    }
    return 1;
}

// find next prime p, p > k
int find_next_prime(int k)
{
    int p = k + 1;
    while (!is_prime(p))
    {
        p++;
    }
    return p;
}

// calculates greatest common divisor of a and b
int gcd(int a, int b)
{
    while (b > 0)
    {
        int r = a % b;
        a = b;
        b = r;
    }
    return a;
}

// calculates g, greatest common divisor of a and b,
// and two numbers x and y such that a*x + b*y = g
int gcd_extended(int a, int b, int &x, int &y)
{
    if (a == 0)
    {
        x = 0;
        y = 1;
        return b;
    }

    int x1;
    int y1;
    int g = gcd_extended(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

// find a number b >= k with gcd(a,b)==1
int find_coprime(int a, int k)
{
    for (int b = k; b++;)
    {
        if (gcd(a, b) == 1)
            return b;
    }
    return 0;
}

// berechnet zu a das multiplikative inverse x mod m: a*x mod m == 1
int inv(int a, int m)
{
    int x;
    int y;
    int g = gcd_extended(a, m, x, y);
    assert(g == 1);
    // now a*x+m*y==1. therefore a*x mod m == 1

    int r = x % m;
    if (r < 0)
        return r + m;
    else
        return r;
}

// computes a^b mod m
int power(int a, int b, int m)
{
    int64_t p = 1;
    for (int i = 0; i < b; ++i)
    {
        p = (p * a) % m;
    }
    return (int)p;
}

// is g a primitive root mod p?
int is_primitive_root(int g, int p)
{
    for (int i = 1; i < p - 1; i++)
    {
        if (power(g, i, p) == 1) // g^i mod p
            return 0;            // no primitive root because g does not generate the *whole* mult. group
    }
    return 1;
}

int find_primitive_root(int p)
{
    // we could start with 2, but also with another value
    for (int g = 2; g < p; g++)
    {
        if (is_primitive_root(g, p))
            return g;
    }
    assert(0);
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    /*
    // Testing approach with dummy values from "https://asecuritysite.com/encryption/diffie?val=6%2C15%2C23%2C5"
    int p = find_next_prime(22);     // equivalent to "N" on the testing web site (see link)
    int g = find_primitive_root(p);  // equivalent to "G" on the testing web site (see link)
    int a = 6;                       // equivalent to "X" on the testing web site (see link)
    int A = power(g, a, p);          // equivalent to "A" on the testing web site (see link)
    int b = 15;                      // equivalent to "Y" on the testing web site (see link)
    int B = power(g, b, p);          // equivalent to "B" on the testing web site (see link)
    int our_secret = power(A, b, p); // equivalent to "same shared key" on the testing web site (see link)

    printf("\n\n####################\n\n");
    printf("p respectively N: %i\n", p);
    printf("g respectively G: %i\n", g);
    printf("a respectively X: %i\n", a);
    printf("A respectively A: %i\n", A);
    printf("b respectively Y: %i\n", b);
    printf("B respectively B: %i\n", B);
    printf("our_secret respectively same shared key: %i\n", our_secret);
    printf("\n####################\n\n\n");

    // Output:
    // ####################
    // 
    // p respectively N: 23
    // g respectively G: 5
    // a respectively X: 6
    // A respectively A: 8
    // b respectively Y: 15
    // B respectively B: 19
    // our_secret respectively respectively : 2
    // 
    // ####################
    */

    int p = find_next_prime(30003);
    int g = find_primitive_root(p);
    int A = 1103;
    int b = 123456;
    int B = power(g, b, p);
    int our_secret = power(A, b, p);

    printf("\n\n####################\n\n");
    printf("p: %i\n", p);
    printf("g: %i\n", g);
    printf("A: %i\n", A);
    printf("b: %i\n", b);
    printf("B: %i\n", B);
    printf("our_secret: %i\n", our_secret);
    
    int A_bruteforce = -1;

    for (int a = 0; a < 10000; a++)
    {
        A_bruteforce = power(g, a, p);
        if (A_bruteforce == A)
        {
            printf("\nBruteforcing the secret a was successful!\n\n");
            printf("A_brutefore: %i\n", A_bruteforce);
            printf("a: %i\n", a);
            a = 10001;
        }
    }

    printf("\n####################\n\n\n");

    return 0; // shall be 0, the same
}