// android_backtrace.cpp
//
// Signal-handler-based native stack unwinder for Android.
// Prints each ancestor frame of the faulting PC as:
//     #NN pc <offset> <path/to/lib.so> (symbol+sym_offset)
//
// Build (example, arm64):
//   clang++ -std=c++17 -O0 -g -fno-omit-frame-pointer \
//       -shared -o libcrashtest.so android_backtrace.cpp -llog
//
// -fno-omit-frame-pointer is required if you use the manual FP-walk path.

#include <android/log.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <csignal>
#include <ucontext.h>
#include <unistd.h>
#include <unwind.h>
#include <cstdio>

#include <cinttypes>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <jni.h>

#define TAG "Athena"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Architecture-specific register extraction from ucontext_t
// ---------------------------------------------------------------------------

#if defined(__aarch64__)
static inline uintptr_t ctx_pc(const ucontext_t* ctx) { return ctx->uc_mcontext.pc; }
static inline uintptr_t ctx_lr(const ucontext_t* ctx) { return ctx->uc_mcontext.regs[30]; }
static inline uintptr_t ctx_fp(const ucontext_t* ctx) { return ctx->uc_mcontext.regs[29]; }
#else
#error "Unsupported architecture"
#endif

// ---------------------------------------------------------------------------
// Symbolization: resolve an address to "lib.so + offset (symbol + offset)"
// ---------------------------------------------------------------------------

static void print_frame(int index, uintptr_t pc) {
    Dl_info info;
    std::memset(&info, 0, sizeof(info));

    if (dladdr(reinterpret_cast<void*>(pc), &info) && info.dli_fname) {
        uintptr_t lib_base = reinterpret_cast<uintptr_t>(info.dli_fbase);
        uintptr_t lib_off = pc - lib_base;

        char sym_buf[256] = {0};
        if (info.dli_sname) {
            int status = 0;
            char* demangled = abi::__cxa_demangle(info.dli_sname, nullptr, nullptr, &status);
            const char* name = (status == 0 && demangled) ? demangled : info.dli_sname;
            uintptr_t sym_off = pc - reinterpret_cast<uintptr_t>(info.dli_saddr);
            snprintf(sym_buf, sizeof(sym_buf), " (%s+0x%" PRIxPTR ")", name, sym_off);
            free(demangled);
        }

        LOGF("  #%02d pc 0x%016" PRIxPTR "  %s (0x%" PRIxPTR ")%s",
             index, lib_off, info.dli_fname, lib_base, sym_buf);
    } else {
        LOGF("  #%02d pc 0x%016" PRIxPTR "  <unknown>", index, pc);
    }
}

// ---------------------------------------------------------------------------
// Method 1 (preferred): _Unwind_Backtrace using CFI/.eh_frame data.
// Works correctly even without frame pointers. This is what
// breakpad/crashpad and most Android crash reporters use.
// ---------------------------------------------------------------------------

struct BacktraceState {
    void** frames;
    int frame_count;
    int max_frames;
};

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context* ctx, void* arg) {
    auto* state = reinterpret_cast<BacktraceState*>(arg);
    if (state->frame_count >= state->max_frames) {
        return _URC_END_OF_STACK;
    }
    uintptr_t pc = _Unwind_GetIP(ctx);
    if (pc) {
        state->frames[state->frame_count++] = reinterpret_cast<void*>(pc);
    }
    return _URC_NO_REASON;
}

static void dump_backtrace_unwind(int max_frames = 32) {
    void* frames[64];
    if (max_frames > 64) max_frames = 64;

    BacktraceState state{frames, 0, max_frames};
    _Unwind_Backtrace(unwind_callback, &state);

    LOGF("--- backtrace (_Unwind_Backtrace) ---");
    for (int i = 0; i < state.frame_count; ++i) {
        print_frame(i, reinterpret_cast<uintptr_t>(frames[i]));
    }
}

// ---------------------------------------------------------------------------
// Method 2: manual frame-pointer chain walk from a ucontext_t, e.g. inside
// a SIGSEGV handler where you want to unwind from the exact faulting frame.
//
// AAPCS64 frame layout (also true in practice for most non-leaf x86_64/ARM32
// frames built with -fno-omit-frame-pointer):
//     [fp + 0]  -> previous fp
//     [fp + 8]  -> return address (lr)
//
// Nested faults while dereferencing bad pointers are caught with
// sigsetjmp/siglongjmp instead of crashing the crash handler.
// ---------------------------------------------------------------------------

static sigjmp_buf g_walk_jmpbuf;
static volatile sig_atomic_t g_walking = 0;

static void walk_fault_handler(int) {
    if (g_walking) {
        siglongjmp(g_walk_jmpbuf, 1);
    }
    _exit(128);  // re-fault outside of the walk: bail out hard
}

static void dump_backtrace_manual(const ucontext_t* ctx, int max_frames = 32) {
    struct sigaction sa{}, old_sa{};
    sa.sa_handler = walk_fault_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa);

    LOGF("--- backtrace (manual FP walk) ---");

    uintptr_t pc = ctx_pc(ctx);
    uintptr_t fp = ctx_fp(ctx);
    uintptr_t lr = ctx_lr(ctx);

    print_frame(0, pc);
    int index = 1;

    // First ancestor is often just the link register (leaf-call case).
    if (lr && lr != pc && index < max_frames) {
        print_frame(index++, lr);
    }

    while (fp && index < max_frames) {
        g_walking = 1;
        if (sigsetjmp(g_walk_jmpbuf, 1) != 0) {
            LOGF("  <fault while reading fp chain, stopping>");
            break;
        }

        // Basic sanity: frame pointers must be non-null and word-aligned.
        if (fp == 0 || (fp & (sizeof(void*) - 1)) != 0) {
            break;
        }

        uintptr_t* frame = reinterpret_cast<uintptr_t*>(fp);
        uintptr_t next_fp = frame[0];
        uintptr_t ret_addr = frame[1];

        g_walking = 0;

        if (ret_addr == 0) {
            break;
        }
        print_frame(index++, ret_addr);

        if (next_fp <= fp) {
            // stack should grow toward higher addresses here
            break;
        }
        fp = next_fp;
    }
    g_walking = 0;

    sigaction(SIGSEGV, &old_sa, nullptr);
}

// ---------------------------------------------------------------------------
// The actual crash handler
// ---------------------------------------------------------------------------

static void crash_handler(int signum, siginfo_t* info, void* ucontext) {
    auto* ctx = reinterpret_cast<ucontext_t*>(ucontext);

    LOGF("*** Fatal signal %d (%s), code %d, fault addr 0x%" PRIxPTR " ***",
         signum, strsignal(signum), info->si_code,
         reinterpret_cast<uintptr_t>(info->si_addr));

    // Prefer CFI-based unwinding; it's more reliable across ABIs/optimization
    // levels. If you suspect corrupted unwind tables or need the exact
    // faulting frame guaranteed, use the manual walk instead/as well.
    dump_backtrace_unwind();
    dump_backtrace_manual(ctx);

    // Re-raise with default disposition so the OS still produces a tombstone
    // / core dump and the process terminates as expected.
    signal(signum, SIG_DFL);
    raise(signum);
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

static uint8_t g_altstack[SIGSTKSZ * 4];

static void install_crash_handler() {
    stack_t ss{};
    ss.ss_sp = g_altstack;
    ss.ss_size = sizeof(g_altstack);
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);

    struct sigaction sa{};
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    const int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTRAP};
    for (int sig : signals) {
        sigaction(sig, &sa, nullptr);
    }
    LOGI("Athena initialized!");
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad");
    install_crash_handler();
    return JNI_VERSION_1_6;
}

// ---------------------------------------------------------------------------
// Example usage
// ---------------------------------------------------------------------------

#ifdef BACKTRACE_DEMO_MAIN
__attribute__((noinline)) void level3() {
  int* p = nullptr;
  *p = 42;  // trigger SIGSEGV
}
__attribute__((noinline)) void level2() { level3(); }
__attribute__((noinline)) void level1() { level2(); }

int main() {
  install_crash_handler();
  level1();
  return 0;
}
#endif