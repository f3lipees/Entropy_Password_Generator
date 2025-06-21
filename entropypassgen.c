#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#define MIN_PRIME 10000000
#define MAX_PRIME 100000000
#define MILLER_RABIN_ITERATIONS 40
#define PASSWORD_LENGTH 20
#define MAX_RETRIES 3
#define ENTROPY_BUFFER_SIZE 1024

typedef unsigned long long int uint64;

static volatile sig_atomic_t exit_requested = 0;

#ifdef _WIN32
BOOL WINAPI ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT) {
        exit_requested = 1;
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int signal) {
    exit_requested = 1;
}
#endif

void sleep_ms(int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

void print_progress_bar(int percentage) {
    int bar_width = 50;
    int filled_length = bar_width * percentage / 100;

    printf("\r[");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled_length) printf("#");
        else printf(" ");
    }
    printf("] %3d%%", percentage);
    fflush(stdout);
}

void clear_line() {
    printf("\r%*s\r", 80, "");
}

uint64 seed_prng() {
    uint64 seed = 0;

#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    seed ^= ((uint64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    seed ^= GetCurrentProcessId();
    seed ^= (uint64)clock();
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    seed ^= ((uint64)ts.tv_sec << 32) | ts.tv_nsec;
    seed ^= ((uint64)getpid() << 32) | getppid();
    seed ^= (uint64)clock();
#endif

    srand((unsigned int)seed);
    return seed;
}

uint64 get_entropy() {
    static bool prng_seeded = false;
    static unsigned char entropy_pool[ENTROPY_BUFFER_SIZE];
    static size_t entropy_index = 0;
    static uint64 counter = 0;
    uint64 result = 0;
    int success = 0;

    if (!prng_seeded) {
        seed_prng();
        memset(entropy_pool, 0, ENTROPY_BUFFER_SIZE);
        prng_seeded = true;
    }

    counter++;

#ifdef _WIN32
    HCRYPTPROV hCryptProv;
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hCryptProv, sizeof(result), (BYTE*)&result)) {
            success = 1;
        }
        CryptReleaseContext(hCryptProv, 0);
    }
#else
    int dev_random = open("/dev/urandom", O_RDONLY);
    if (dev_random != -1) {
        if (read(dev_random, &result, sizeof(result)) == sizeof(result)) {
            success = 1;
        }
        close(dev_random);
    }

    if (!success) {
        dev_random = open("/dev/random", O_RDONLY | O_NONBLOCK);
        if (dev_random != -1) {
            if (read(dev_random, &result, sizeof(result)) == sizeof(result)) {
                success = 1;
            }
            close(dev_random);
        }
    }
#endif

    if (!success) {
        FILE* sources[] = {
            fopen("/proc/stat", "rb"),
            fopen("/proc/interrupts", "rb"),
            fopen("/proc/meminfo", "rb"),
            fopen("/proc/self/status", "rb")
        };

        size_t entropy_added = 0;
        for (int i = 0; i < 4; i++) {
            if (sources[i]) {
                while (entropy_added < ENTROPY_BUFFER_SIZE && !feof(sources[i])) {
                    size_t bytes_read = fread(&entropy_pool[entropy_added], 1,
                                            ENTROPY_BUFFER_SIZE - entropy_added, sources[i]);
                    entropy_added += bytes_read;
                    if (bytes_read == 0) break;
                }
                fclose(sources[i]);
            }
        }

        if (entropy_added > 0) {
            memcpy(&result, &entropy_pool[entropy_index % entropy_added], sizeof(result));
            entropy_index = (entropy_index + sizeof(result)) % entropy_added;
            success = 1;
        }
    }

    if (!success) {
        clock_t start = clock();
        for (volatile int i = 0; i < 1000000; i++) {}
        clock_t end = clock();

        result ^= ((uint64)end << 32) | start;
        result ^= ((uint64)time(NULL) << 40) | counter;
    }

    result ^= ((uint64)rand() << 32) | rand();
    return result;
}

uint64 random_u64() {
    return get_entropy();
}

uint64 mod_mul(uint64 a, uint64 b, uint64 mod) {
    uint64 res = 0;
    a %= mod;

    while (b) {
        if (b & 1) {
            res = (res + a) % mod;
        }
        a = (a << 1) % mod;
        b >>= 1;
    }

    return res;
}

uint64 mod_pow(uint64 base, uint64 exponent, uint64 modulus) {
    uint64 result = 1;
    base = base % modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exponent >>= 1;
    }

    return result;
}

bool miller_rabin_test(uint64 n, uint64 d, int r, uint64 a) {
    uint64 x = mod_pow(a, d, n);

    if (x == 1 || x == n - 1) {
        return true;
    }

    for (int i = 0; i < r - 1; i++) {
        x = mod_mul(x, x, n);
        if (x == n - 1) {
            return true;
        }
    }

    return false;
}

bool is_prime(uint64 n) {
    if (n <= 1 || n == 4) {
        return false;
    }
    if (n <= 3) {
        return true;
    }
    if (n % 2 == 0) {
        return false;
    }

    uint64 d = n - 1;
    int r = 0;

    while (d % 2 == 0) {
        d >>= 1;
        r++;
    }

    const uint64 small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41};
    for (int i = 0; i < sizeof(small_primes)/sizeof(small_primes[0]); i++) {
        if (n == small_primes[i]) {
            return true;
        }
        if (n % small_primes[i] == 0) {
            return false;
        }
    }

    for (int i = 0; i < MILLER_RABIN_ITERATIONS; i++) {
        uint64 a = 2 + random_u64() % (n - 4);
        if (!miller_rabin_test(n, d, r, a)) {
            return false;
        }
    }

    return true;
}

uint64 generate_random_prime(uint64 min, uint64 max) {
    uint64 range = max - min + 1;
    uint64 candidate;
    int attempts = 0;

    printf("\nGenerating secure prime number\n");

    do {
        if (exit_requested) {
            return 0;
        }

        candidate = min + (random_u64() % range);
        if (candidate % 2 == 0) {
            candidate++;
        }

        attempts++;
        if (attempts % 10 == 0) {
            print_progress_bar((attempts > 1000) ? 99 : (attempts / 10));
        }
    } while (!is_prime(candidate));

    clear_line();
    printf("Prime found: %llu\n", candidate);

    return candidate;
}

char* format_user_password(uint64 number) {
    static char password[PASSWORD_LENGTH + 1];
    const char* upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    const char* lower = "abcdefghijkmnopqrstuvwxyz";
    const char* digits = "23456789";
    const char* special = "!@#$%^&*-+_=?";

    uint64 entropy = number;

    for (int i = 0; i < PASSWORD_LENGTH; i++) {
        const char* charset;
        int charset_length;

        switch ((entropy >> 60) % 4) {
            case 0:
                charset = upper;
                charset_length = strlen(upper);
                break;
            case 1:
                charset = lower;
                charset_length = strlen(lower);
                break;
            case 2:
                charset = digits;
                charset_length = strlen(digits);
                break;
            case 3:
                charset = special;
                charset_length = strlen(special);
                break;
        }

        password[i] = charset[(entropy >> 48) % charset_length];
        entropy = (entropy << 16) | ((random_u64() >> 48) & 0xFFFF);
    }

    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (int i = 0; i < PASSWORD_LENGTH; i++) {
        char c = password[i];
        if (strchr(upper, c)) has_upper = 1;
        else if (strchr(lower, c)) has_lower = 1;
        else if (strchr(digits, c)) has_digit = 1;
        else if (strchr(special, c)) has_special = 1;
    }

    if (!has_upper) password[random_u64() % PASSWORD_LENGTH] = upper[random_u64() % strlen(upper)];
    if (!has_lower) password[random_u64() % PASSWORD_LENGTH] = lower[random_u64() % strlen(lower)];
    if (!has_digit) password[random_u64() % PASSWORD_LENGTH] = digits[random_u64() % strlen(digits)];
    if (!has_special) password[random_u64() % PASSWORD_LENGTH] = special[random_u64() % strlen(special)];

    password[PASSWORD_LENGTH] = '\0';
    return password;
}

void print_banner() {
    printf("\n+--------------------------------------------+\n");
    printf("|      Entropy Password Generator       |\n");
    printf("+--------------------------------------------+\n\n");
}

int generate_secure_password() {
    uint64 p = 0, q = 0;

    printf("Initiating secure password generation sequence\n");
    sleep_ms(500);

    int retries = 0;
    while (p == 0 && retries < MAX_RETRIES) {
        p = generate_random_prime(MIN_PRIME, MAX_PRIME);
        if (p == 0 && exit_requested) {
            return 1;
        } else if (p == 0) {
            retries++;
            printf("Failed to generate prime. Retrying (%d/%d)...\n", retries, MAX_RETRIES);
        }
    }

    if (p == 0) {
        fprintf(stderr, "ERROR: Failed to generate first prime after %d attempts\n", MAX_RETRIES);
        return 1;
    }

    retries = 0;
    while ((q == 0 || q == p) && retries < MAX_RETRIES) {
        q = generate_random_prime(MIN_PRIME, MAX_PRIME);
        if (q == 0 && exit_requested) {
            return 1;
        } else if (q == 0 || q == p) {
            retries++;
            printf("Failed to generate second prime. Retrying (%d/%d)...\n", retries, MAX_RETRIES);
        }
    }

    if (q == 0 || q == p) {
        fprintf(stderr, "ERROR: Failed to generate second prime after %d attempts\n", MAX_RETRIES);
        return 1;
    }

    printf("\nComputing secure product...\n");
    sleep_ms(500);

    uint64 product = p * q;

    printf("\n+--------------------------------------------+\n");
    printf("|            PASSWORD INFORMATION            |\n");
    printf("+--------------------------------------------+\n");
    printf("| First Prime (p):  %-24llu |\n", p);
    printf("| Second Prime (q): %-24llu |\n", q);
    printf("| Product (p×q):    %-24llu |\n", product);
    printf("+--------------------------------------------+\n");

    char* user_password = format_user_password(product);
    printf("| YOUR PASSWORD:    %-24s |\n", user_password);
    printf("+--------------------------------------------+\n");

    printf("\nTechnical formats:\n");

    char hex_password[17];
    snprintf(hex_password, sizeof(hex_password), "%016llx", product);
    printf("  HEX: %s\n", hex_password);

    printf("  BIN: ");
    for (int i = 60; i >= 0; i -= 4) {
        printf("%x", (int)((product >> i) & 0xF));
    }
    printf("\n");

    return 0;
}

void initialize_system() {
#ifdef _WIN32
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif

    seed_prng();

    uint64 entropy_check = 0;
    for (int i = 0; i < 3; i++) {
        entropy_check |= random_u64();
    }

    if (entropy_check == 0) {
        fprintf(stderr, "CRITICAL ERROR: Entropy generation failure\n");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    int return_code = 0;

    initialize_system();
    print_banner();

    if (argc > 1 && strcmp(argv[1], "--batch") == 0) {
        int num_passwords = 1;
        if (argc > 2) {
            num_passwords = atoi(argv[2]);
            if (num_passwords <= 0) num_passwords = 1;
            if (num_passwords > 10) num_passwords = 10;
        }

        for (int i = 0; i < num_passwords && !exit_requested; i++) {
            printf("\nGenerating password %d of %d:\n", i+1, num_passwords);
            return_code = generate_secure_password();
            if (return_code != 0) break;
        }
    } else {
        return_code = generate_secure_password();
    }

    if (exit_requested) {
        printf("\nPassword generation interrupted.\n");
    } else if (return_code == 0) {
        printf("\nPassword generation completed successfully.\n");
    } else {
        printf("\nPassword generation failed.\n");
    }

    if (!exit_requested && (argc <= 1 || strcmp(argv[1], "--batch") != 0)) {
        printf("\nPress Enter to exit...");
        getchar();
    }

    return return_code;
}
