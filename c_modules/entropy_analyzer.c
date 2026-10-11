#define BUILDING_ENTROPY_DLL
#include "entropy_analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#ifndef M_LN2
#define M_LN2 0.693147180559945309417
#endif

/* Log2 fallback for older MSVC or C standards */
static double safe_log2(double x) {
    if (x <= 0.0) return 0.0;
    return log(x) / M_LN2;
}

ENTROPY_API double calculate_shannon_entropy(const char *password) {
    if (password == NULL) {
        return 0.0;
    }
    
    size_t len = strlen(password);
    if (len == 0) {
        return 0.0;
    }

    /* Frequency count table for 256 ASCII characters */
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        freq[c]++;
    }

    double entropy_per_char = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            entropy_per_char -= p * safe_log2(p);
        }
    }

    /* Total Shannon entropy in bits = length * H(X) */
    return entropy_per_char * (double)len;
}

ENTROPY_API int calculate_strength_score(const char *password) {
    PasswordAnalysisResult res;
    if (analyze_password(password, &res) != 0) {
        return 0;
    }
    return res.score;
}

ENTROPY_API int analyze_password(const char *password, PasswordAnalysisResult *result) {
    if (result == NULL) {
        return -1; /* Invalid argument */
    }

    /* Initialize result fields */
    memset(result, 0, sizeof(PasswordAnalysisResult));

    if (password == NULL || password[0] == '\0') {
        strncpy(result->strength_label, "Empty", sizeof(result->strength_label) - 1);
        return 0;
    }

    size_t len = strlen(password);
    result->length = (int)len;

    int has_lower = 0;
    int has_upper = 0;
    int has_digit = 0;
    int has_symbol = 0;

    int freq[256] = {0};

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        freq[c]++;

        if (islower(c)) {
            result->lowercase_count++;
            has_lower = 1;
        } else if (isupper(c)) {
            result->uppercase_count++;
            has_upper = 1;
        } else if (isdigit(c)) {
            result->digit_count++;
            has_digit = 1;
        } else {
            result->symbol_count++;
            has_symbol = 1;
        }
    }

    /* Determine character pool size based on active character classes */
    int pool_size = 0;
    if (has_lower) pool_size += 26;
    if (has_upper) pool_size += 26;
    if (has_digit) pool_size += 10;
    if (has_symbol) pool_size += 33; /* Standard ASCII special characters */
    if (pool_size == 0) pool_size = 1;
    result->pool_size = pool_size;

    /* Compute Combinatorial Pool Entropy: E_pool = length * log2(pool_size) */
    result->pool_entropy = (double)len * safe_log2((double)pool_size);

    /* Compute Shannon Information Entropy */
    double shannon_per_char = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            shannon_per_char -= p * safe_log2(p);
        }
    }
    result->shannon_entropy = shannon_per_char * (double)len;

    /* Estimate crack time assuming modern offline cracking speed: 10^10 hashes/sec */
    /* Estimated combinations = 2^(pool_entropy) */
    /* crack_time_seconds = combinations / (2 * 10^10) for 50% crack probability */
    if (result->pool_entropy >= 120.0) {
        result->crack_time_seconds = 1e25; /* Practically infinite */
    } else {
        double combinations = pow(2.0, result->pool_entropy);
        result->crack_time_seconds = combinations / (2.0 * 10000000000.0);
    }

    /* Score Calculation (0 - 100 scale) */
    /* Based on NIST SP 800-63B and information theory */
    double effective_entropy = (result->shannon_entropy * 0.6) + (result->pool_entropy * 0.4);
    
    /* Penalties for repetitive characters */
    int max_repeat = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > max_repeat) {
            max_repeat = freq[i];
        }
    }
    if ((double)max_repeat / (double)len > 0.5 && len > 3) {
        effective_entropy -= 15.0;
    }

    /* Variety bonus */
    int variety = has_lower + has_upper + has_digit + has_symbol;
    if (variety == 4 && len >= 12) {
        effective_entropy += 10.0;
    }

    int score = (int)((effective_entropy / 80.0) * 100.0);
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    result->score = score;

    /* Qualitative Label Assignment */
    if (score < 25) {
        strncpy(result->strength_label, "Very Weak", sizeof(result->strength_label) - 1);
    } else if (score < 50) {
        strncpy(result->strength_label, "Weak", sizeof(result->strength_label) - 1);
    } else if (score < 70) {
        strncpy(result->strength_label, "Moderate", sizeof(result->strength_label) - 1);
    } else if (score < 88) {
        strncpy(result->strength_label, "Strong", sizeof(result->strength_label) - 1);
    } else {
        strncpy(result->strength_label, "Very Strong", sizeof(result->strength_label) - 1);
    }

    return 0; /* Success */
}
