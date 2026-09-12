#include "harness.h"
#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"
#include <stdlib.h>
#include <string.h>

// libinjection reads a few bytes past the end of the input on some adversarial
// inputs (an ASan-confirmed over-read in htmlencode_startswith, reached from
// libinjection_is_xss). Past the buffer the bytes are indeterminate, so the
// verdict is not reproducible across builds. Copy the input into a zeroed,
// over-allocated buffer so any such read lands on defined zero bytes and the
// C result is deterministic. The differential then compares against a stable
// C answer rather than stack garbage.
#define HARNESS_PAD 16

static char* padded_copy(const char* input, size_t input_len) {
    char* buf = (char*)calloc(input_len + HARNESS_PAD, 1);
    if (buf && input_len) {
        memcpy(buf, input, input_len);
    }
    return buf;
}

sqli_result_t harness_detect_sqli(const char* input, size_t input_len, int flags) {
    sqli_result_t result = {0};
    struct libinjection_sqli_state state;

    char* buf = padded_copy(input, input_len);

    // Initialize state
    libinjection_sqli_init(&state, buf, input_len, flags);

    // Detect SQL injection
    result.is_sqli = libinjection_is_sqli(&state);
    
    // Always get fingerprint from state, regardless of injection status
    // Copy fingerprint and ensure null termination
    memcpy(result.fingerprint, state.fingerprint, 8);
    result.fingerprint[8] = '\0';
    
    // Find actual end of fingerprint (remove trailing nulls)
    int end = 7;
    while (end >= 0 && result.fingerprint[end] == '\0') {
        end--;
    }
    if (end >= 0) {
        result.fingerprint[end + 1] = '\0';
    } else {
        result.fingerprint[0] = '\0';
    }

    free(buf);
    return result;
}

xss_result_t harness_detect_xss(const char* input, size_t input_len, int flags) {
    xss_result_t result = {0};

    char* buf = padded_copy(input, input_len);

    // Detect XSS
    result.is_xss = libinjection_xss(buf, input_len);

    free(buf);

    // Note: flags parameter currently unused but kept for API consistency
    (void)flags;

    return result;
}

const char* harness_version(void) {
    return libinjection_version();
}