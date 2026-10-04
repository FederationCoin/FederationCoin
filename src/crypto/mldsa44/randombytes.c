/* Seeded bytes for ML-DSA-44 key generation. Signing randomness is the
 * all-zero string once the seed has been consumed, which is the
 * deterministic FIPS 204 signing input. Public domain, same terms as
 * the PQClean sources beside this file. */
#include "randombytes.h"

#include <string.h>

#if defined(_MSC_VER)
#define MLDSA44_THREAD_LOCAL __declspec(thread)
#else
#define MLDSA44_THREAD_LOCAL _Thread_local
#endif

static MLDSA44_THREAD_LOCAL const uint8_t* g_next;
static MLDSA44_THREAD_LOCAL size_t g_left;

void mldsa44_use_seed(const uint8_t* seed, size_t len)
{
    g_next = seed;
    g_left = len;
}

int PQCLEAN_randombytes(uint8_t* output, size_t n)
{
    if (g_next != NULL && g_left >= n) {
        memcpy(output, g_next, n);
        g_next += n;
        g_left -= n;
        return 0;
    }
    memset(output, 0, n);
    return 0;
}
