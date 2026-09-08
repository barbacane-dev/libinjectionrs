#![no_main]
use libfuzzer_sys::fuzz_target;
use libinjectionrs::detect_xss as rust_detect_xss;
use std::os::raw::c_char;

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Shared with comparison-bin/tests/differential.rs so there is one list.
include!("../../known_divergences.rs");

fn call_c_xss(input: &[u8]) -> Result<bool, ()> {
    // The harness takes an explicit length, so the input does not need to be
    // NUL-terminated and may contain NUL bytes. Going through CString meant
    // every input containing a NUL was skipped, which is a shape a WAF
    // receives routinely and a classic filter evasion.
    unsafe {
        let result = harness_detect_xss(
            input.as_ptr() as *const c_char,
            input.len(),
            0,
        );
        
        Ok(result.is_xss != 0)
    }
}

fuzz_target!(|data: &[u8]| {
    let rust_result = rust_detect_xss(data);
    let rust_is_injection = rust_result.is_injection();
    
    if let Ok(c_is_injection) = call_c_xss(data) {
        // The implementations should agree on whether input is XSS
        if rust_is_injection != c_is_injection {
            // Convert to string for debugging if possible
            let debug_input = String::from_utf8_lossy(data);
            
            // A fresh instance of an already-understood class is not news;
            // anything else is. Without this the fuzzer would stop at the
            // first known bug on every run and never reach new ground.
            if is_known_divergence(data, KNOWN_XSS_DIVERGENCES) {
                return;
            }

            // Report every other divergence. Capping this at 1000 bytes meant
            // a divergence on a longer input was detected and then discarded,
            // and length is exactly where two parsers drift apart.
            let shown: String = debug_input.chars().take(2000).collect();
            panic!(
                "Differential detected! len={}, Rust: {}, C: {}, input: {:?}",
                data.len(), rust_is_injection, c_is_injection, shown
            );
        }
    }
});