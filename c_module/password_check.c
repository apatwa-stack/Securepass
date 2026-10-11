#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

/*
 * C Function: check_password_strength
 * Takes a password string, counts character types in C,
 * and calculates a strength score from 0 to 100.
 */
EXPORT int check_password_strength(const char *password) {
    if (!password) {
        return 0;
    }

    int len = (int)strlen(password);
    if (len == 0) {
        return 0;
    }

    int has_upper = 0;
    int has_lower = 0;
    int has_digit = 0;
    int has_special = 0;

    // Loop through each character in the string
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (isupper(c)) {
            has_upper = 1;
        } else if (islower(c)) {
            has_lower = 1;
        } else if (isdigit(c)) {
            has_digit = 1;
        } else {
            has_special = 1;
        }
    }

    // Base score based on length (4 points per character)
    int score = len * 4;

    // Bonus points for variety
    if (has_upper) score += 10;
    if (has_lower) score += 10;
    if (has_digit) score += 10;
    if (has_special) score += 15;

    // Cap at 100
    if (score > 100) {
        score = 100;
    }

    return score;
}
