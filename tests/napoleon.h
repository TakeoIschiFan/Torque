#pragma once

#include <stdio.h>
#include <stdlib.h>

#define NAP_TEST __attribute__((constructor)) static void

// Color codes as compile-time constants
#define NAP_COLOR_CODE "\x1B"
#define NAP_COLOR_RED "[1;31m"
#define NAP_COLOR_GREEN "[1;32m"
#define NAP_COLOR_RESET "[0m"

// Declare shared variables
extern int nap_passes;
extern int nap_fails;
extern int nap_skipped;

#define nap_assert(expression)                                                 \
    do {                                                                       \
        if (!(expression)) {                                                   \
            nap_fails++;                                                       \
            printf("Assertion failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   #expression);                                               \
            printf("%s%sFAIL%s%s: %s %s (line %d): %s (actual value: %d)\n",   \
                   NAP_COLOR_CODE, NAP_COLOR_RED, NAP_COLOR_CODE,              \
                   NAP_COLOR_RESET, __FILE__, __func__, __LINE__, #expression, \
                   (int)(expression));                                         \
        } else {                                                               \
            nap_passes++;                                                      \
        }                                                                      \
    } while (0)

// Function declarations
int nap_execute(void);

#ifdef NAPOLEON_IMPLEMENTATION

// Define shared variables
int nap_passes = 0;
int nap_fails = 0;
int nap_skipped = 0;

int nap_execute(void) {
    printf("\n");
    if (nap_fails) {
        printf("%s%sNOT OK%s%s (passed:%d, failed:%d, total:%d, skipped:%d)\n",
               NAP_COLOR_CODE, NAP_COLOR_RED, NAP_COLOR_CODE, NAP_COLOR_RESET,
               nap_passes, nap_fails, nap_passes + nap_fails + nap_skipped,
               nap_skipped);
        return -1;
    } else {
        printf("%s%sOK%s%s (total:%d, skipped:%d)\n", NAP_COLOR_CODE,
               NAP_COLOR_GREEN, NAP_COLOR_CODE, NAP_COLOR_RESET, nap_passes,
               nap_skipped);
        return 0;
    }
}

#endif
