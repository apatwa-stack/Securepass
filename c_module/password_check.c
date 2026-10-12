#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

EXPORT int check_password_strength(const char *password) {
    if (!password || !*password) return 0;
    int len = (int)strlen(password), upper = 0, lower = 0, digit = 0, special = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        if (isupper(c)) upper = 1;
        else if (islower(c)) lower = 1;
        else if (isdigit(c)) digit = 1;
        else special = 1;
    }
    int score = len * 4 + upper * 10 + lower * 10 + digit * 10 + special * 15;
    return score > 100 ? 100 : score;
}
