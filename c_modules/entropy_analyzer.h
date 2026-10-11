#ifndef ENTROPY_ANALYZER_H
#define ENTROPY_ANALYZER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
  #ifdef BUILDING_ENTROPY_DLL
    #define ENTROPY_API __declspec(dllexport)
  #else
    #define ENTROPY_API __declspec(dllimport)
  #endif
#else
  #define ENTROPY_API __attribute__((visibility("default")))
#endif

/**
 * Structure containing detailed password security metrics calculated in C.
 */
typedef struct {
    int length;
    int uppercase_count;
    int lowercase_count;
    int digit_count;
    int symbol_count;
    int pool_size;
    double shannon_entropy;      /* Shannon entropy in bits */
    double pool_entropy;         /* Combinatorial pool entropy in bits */
    double crack_time_seconds;   /* Estimated offline brute-force time in seconds (10^10 hashes/sec) */
    int score;                   /* Scaled security score from 0 to 100 */
    char strength_label[32];     /* "Very Weak", "Weak", "Moderate", "Strong", "Very Strong" */
} PasswordAnalysisResult;

/**
 * Computes Shannon entropy of an ASCII string in C.
 * H = -sum(p_i * log2(p_i)) * length
 * @param password Null-terminated password string.
 * @return Total Shannon entropy in bits, or -1.0 on error.
 */
ENTROPY_API double calculate_shannon_entropy(const char *password);

/**
 * Computes a standardized strength score (0-100) based on entropy, diversity, and penalties.
 * @param password Null-terminated password string.
 * @return Integer score between 0 and 100.
 */
ENTROPY_API int calculate_strength_score(const char *password);

/**
 * Performs full multi-dimensional password analysis and populates PasswordAnalysisResult.
 * @param password Null-terminated password string.
 * @param result Pointer to pre-allocated PasswordAnalysisResult structure.
 * @return 0 on success, non-zero error code otherwise.
 */
ENTROPY_API int analyze_password(const char *password, PasswordAnalysisResult *result);

#ifdef __cplusplus
}
#endif

#endif /* ENTROPY_ANALYZER_H */
