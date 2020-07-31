/*
    build this code on Ubuntu 18.04 (x86 PC) with:
    $g++ 4_rsa.cpp -o exe

    then run the executable on Ubuntu 18.04 (x86 PC) with:
    $./exe

    --------------------------------------------------------------------------------

    relevant output:

    ########################################

    Messages of Alice and Bob:
    msg: 4
    enc: 31
    dec: 4


    Professor's message:
    enc: 673379914
    dec: 666666

    ########################################
    
    --------------------------------------------------------------------------------

    "is_prime()" analysis:

    Runtime complexity of "is_prime()"
    is about O(sqrt(n)).

    The best known "primality test" algorithm
    is the "AKS primality test"
    with a runtime complexity of O((log n)^6).

    Own observations to "is_prime()":

    It is not necessary to divide the input by even numbers,
    since it is sufficient to divide it once by 2
    (if a number is divisible by a even number,
    it is also divisible by 2):

    int is_prime(int p)
    {
        if (p % 2 == 0) return 0;

        for (int t = 3; t * t <= p; t + 2)
        {
            if (p % t == 0) return 0;
        }
        return 1;
    }

    References:

    https://softwareengineering.stackexchange.com/questions/197374/what-is-the-time-complexity-of-the-algorithm-to-check-if-a-number-is-prime
    https://www.quora.com/Whats-the-best-algorithm-to-check-if-a-number-is-prime
    https://en.wikipedia.org/wiki/Primality_test
    https://de.wikipedia.org/wiki/Primzahltest
    https://en.wikipedia.org/wiki/AKS_primality_test

    --------------------

    find_next_prime() analysis:

    Runtime complexity of "find_next_prime()"
    is yet not known to humanity.
    Furthermore this implementation
    also depends on "is_prime()".

    There is no efficient and scalable algorithm known.
    There are some sieve-based algorithms for small prime numbers
    and there is also the possibility to use and maintain
    a list of prime numbers but the drawbacks are obvious.
    If a efficient and scalable method is known,
    please contact the International Mathematical Union ASAP.

    Own observations to "find_next_prime()":

    It is not necessary to test even numbers,
    since even numbers are divisible by 2
    and can not be prime numbers:
    
    int find_next_prime(int k)
    {
        int p;

        if (k % 2 == 0) // if "k" is even, "p" is "k" + 1 -> "p" is odd
            p = k + 1;
        else            // if "k" is odd, "p" is "k" + 2 -> "p" is odd
            p = k + 2;

        while (!is_prime(p))
        {
            p += 2;     // testing just odd numbers
        }
        return p;
    }

    References:

    https://cs.stackexchange.com/questions/10683/what-is-the-time-complexity-of-generating-n-th-prime-number
    https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
    https://cstheory.stackexchange.com/questions/4882/finding-a-prime-greater-than-a-given-bound
    https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes

    --------------------

    gcd() analysis:

    "gcd()" uses the "Euclidean algorithm".
    Runtime complexity of "gcd()"
    is O(log min(a, b)).

    The best known "gcd" algorithm
    is the "Binary GCD algorithm"
    with a runtime complexity of O((log_2 (u, v))^6).
    There seems to be a worst case scenario
    in which the runtime complexity is O(n^2).

    References:

    https://iq.opengenus.org/extended-euclidean-algorithm/
    https://www.quora.com/What-is-the-time-complexity-of-Euclids-GCD-algorithm
    https://en.wikipedia.org/wiki/Binary_GCD_algorithm
    https://xlinux.nist.gov/dads/HTML/binaryGCD.html
    https://lemire.me/blog/2013/12/26/fastest-way-to-compute-the-greatest-common-divisor/
    https://en.wikipedia.org/wiki/Greatest_common_divisor
    https://de.wikipedia.org/wiki/Gr%C3%B6%C3%9Fter_gemeinsamer_Teiler

    --------------------

    gcd_extended() analysis:

    "gcd_extended()" uses the "Extended Euclidean Algorithm".
    Runtime complexity of "gcd_extended()"
    is O(log N) and space complexity is O(1).

    Researching the internet does not reveal 
    any more efficient algorithms (just optimizations).

    References:

    https://iq.opengenus.org/extended-euclidean-algorithm/
    https://www.sciencedirect.com/science/article/pii/S1570866707000585
    https://www.csd.uwo.ca/~mmorenom/CS424/Lectures/FastDivisionAndGcd.html/node6.html
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    https://de.wikipedia.org/wiki/Erweiterter_euklidischer_Algorithmus

    --------------------

    find_coprime() analysis:

    Runtime complexity of "find_coprime()"
    is yet not known.
    Furthermore this implementation
    also depends on "gcd()".

    Researching the internet reveals several optimizations:
    - two even numbers can not be co-prime (both divisible by 2)
    - any two consecutive integers are always coprime
    They are probably more optimizations.
    
    Own observations to "find_coprime()":
    
    Two even numbers can not be co-prime (both divisible by 2):

    int find_coprime(int a, int k)
    {
        if (a % 2 == 0)                      // if "a" is even
        {
            if (k % 2 == 0)                  // if "k" is even
            {
                for (int b = k + 1; b += 2;) // "b" is "k" + 1 -> "b" is odd
                {
                    if (gcd(a, b) == 1) return b;
                }
            }
            else                             // if "k" is odd
            {
                for (int b = k; b += 2;)     // "b" is "k" -> "b" is odd
                {
                    if (gcd(a, b) == 1) return b;
                }
            }
        }
        else                                 // if "a" is odd
        {
            for (int b = k; b++;)
            {
                if (gcd(a, b) == 1) return b;
            }
        }
        return 0;
    }

    References:

    https://www.quora.com/What-is-the-fastest-method-to-check-if-two-numbers-are-coprime
    https://stackoverflow.com/questions/1483404/what-is-the-fastest-way-to-check-if-two-given-numbers-are-coprime
    https://simple.wikipedia.org/wiki/Coprime
    https://en.wikipedia.org/wiki/Coprime_integers

    --------------------

    inv() analysis:

    Runtime complexity of "inv()"
    depends on "gcd_extended()"
    and is in this case O(log N)
    (it is the runtime complexity of "gcd_extended()").

    Using a "Extended Euclidean algorithm"
    is probably the fastest way
    to determine the "Modular multiplicative inverse" yet.

    References:

    https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    https://mathoverflow.net/questions/40997/fast-computation-of-multiplicative-inverse-modulo-q
    https://en.wikipedia.org/wiki/Modular_multiplicative_inverse

    --------------------

    power() analysis:

    Runtime complexity of "power()"
    is O(N) (linear - N is "b").
    "power()" is memory-efficient
    and does not generate as huge numbers
    as the direct way (just calculating "a^b mod m").

    A better "modular exponentiation" algorithm
    is the "right-to-left binary method"
    (the is the "left-to-right binary method" too).
    It uses "exponentiation by squaring"
    and has a runtime complexity of O(log n).

    References:

    https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/modular-exponentiation
    https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation
    https://de.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation
    https://stackoverflow.com/questions/19839457/explanation-of-right-to-left-binary-method-of-modular-arithmetic
    https://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms
    https://math.stackexchange.com/questions/2382011/computational-complexity-of-modular-exponentiation-from-rosens-discrete-mathem
    https://en.wikipedia.org/wiki/Modular_exponentiation
    https://en.wikipedia.org/wiki/Exponentiation_by_squaring

    --------------------

    is_primitive_root() analysis:

    Runtime complexity of "power() calling for loop"
    in "is_primitive_root()"
    is O(N) (linear - N is "p")
    and calls "power()",
    which has a runtime complexity of O(N) (linear - N is "b" is "p").
    Runtime complexity of "is_primitive_root()"
    is O(N^2).

    Internet research revealed:
    Working with just prime numbers as powers
    instead of brute forcing
    should increase the efficiency.

    References:

    https://math.stackexchange.com/questions/156213/practical-method-of-calculating-primitive-roots-modulo-a-prime
    https://math.stackexchange.com/questions/2195687/verify-that-x-is-a-primitive-root-modulo-n
    https://en.wikipedia.org/wiki/Primitive_root_modulo_n
    https://de.wikipedia.org/wiki/Primitivwurzel

    --------------------

    find_primitive_root() analysis:

    Runtime complexity of "is_primitive_root() calling for loop"
    in "find_primitive_root()"
    is O(N) (linear - N is "p")
    and calls "power()",
    which has a runtime complexity of O(N) (linear - N is "p" is "p").
    Runtime complexity of "find_primitive_root()"
    is O(N^3).

    Internet research revealed:
    Working with just prime numbers as powers
    instead of brute forcing
    should increase the efficiency.

    References:

    https://en.wikipedia.org/wiki/Primitive_root_modulo_n#Finding_primitive_roots
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
    // see Paar & Pelzl crypto book page 203

    // Alice generates keys
    int p = find_next_prime(2); // 3
    int q = find_next_prime(8); // 11
    int N = p * q;
    int phi_N = (p - 1) * (q - 1); // 20

    int e = 3;

    // original RSA way
    int d = inv(e, phi_N); // 7

    // Alice publishes N and e

    // Bob encrypts message m to cipher c
    int m = 4;              // the message
    int c = power(m, e, N); // encrypted message

    // alice decrypts c to n
    int n = power(c, d, N); // decrypted message

    assert(m == n);

    printf("\n\n########################################\n\n\n");
    printf("Messages of Alice and Bob:\n");
    printf("msg: %i\n", m);
    printf("enc: %i\n", c);
    printf("dec: %i\n", n);

    /* -- Task ------------------------------------------------------------- */

    c = 673379914;      // encrypted message respectively cipher
    N = 963876449;      // private key
    d = 48190717;       // private key
    n = power(c, d, N); // decrypting message respectively getting plain text

    printf("\n\nProfessor's message:\n");
    printf("enc: %i\n", c);
    printf("dec: %i\n", n);
    printf("\n\n########################################\n\n\n");

    return 0; // shall be 0, the same
}