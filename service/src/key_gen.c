#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>  // Needed for getpid() function
#include <sys/time.h> // Needed for gettimeofday() function

#define N 256  // Bit size for p and q

void generate_random_prime(mpz_t prime, gmp_randstate_t state, mp_bitcnt_t bits) {
    do {
        mpz_urandomb(prime, state, bits);
        mpz_setbit(prime, bits - 1);  // Ensure most significant bit is set for correct bit size
        mpz_nextprime(prime, prime);  // Find the next prime number starting from prime
    } while (mpz_sizeinbase(prime, 2) != bits);  // Ensure exactly N bits
}

int is_prime(mpz_t n, gmp_randstate_t state) {
    return mpz_probab_prime_p(n, 50);
}

void generate_primes(mpz_t p, mpz_t q, gmp_randstate_t state) {
    mpz_t six;
    mpz_init(six);
    mpz_set_ui(six, 6);

    int found = 0;

    while (!found) {
        // Generate random prime p
        generate_random_prime(p, state, N);
        mpz_add(q, p, six);

        // Check if q is prime and both p and q are exactly 256 bits
        if (is_prime(q, state) && is_prime(p, state) && mpz_sizeinbase(p, 2) == N && mpz_sizeinbase(q, 2) == N) {
            found = 1;
        }
    }

    mpz_clear(six);
}

unsigned long long get_seed() {
    //create a seed based on the current time and process ID 
    //(random but if it does happen that we hit same prime there is a check in python that will generate new primes until they are different)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    pid_t pid = getpid();
    unsigned long long seed = ts.tv_sec * 1000000000LL + ts.tv_nsec + pid;

    return seed;
}

int main() {
    // Initialize GMP random state
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    // Seed the random number generator with more randomness
    unsigned long long seed = get_seed();
    gmp_randseed_ui(state, seed);
    
    mpz_t p, q;
    mpz_inits(p, q, NULL);
    
    // Generate random primes
    generate_primes(p, q, state);
    
    // Print the generated primes
    gmp_printf("%Zd\n", p);
    gmp_printf("%Zd\n", q);
    
    // Clear resources
    mpz_clears(p, q, NULL);
    gmp_randclear(state);

    return 0;
}







