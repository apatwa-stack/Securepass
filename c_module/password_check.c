#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif
EXPORT int check_password(const char *password) {
    if (!password || strlen(password) < 6) return 0;
    int upper = 0, lower = 0, digit = 0, special = 0;
    for (int i = 0; password[i]; i++) {
        unsigned char c = (unsigned char)password[i];
        if (isupper(c)) upper = 1;
        else if (islower(c)) lower = 1;
        else if (isdigit(c)) digit = 1;
        else special = 1;
    }
    return (upper && lower && digit && special);
}
