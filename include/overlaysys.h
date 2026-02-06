#pragma once

#include <x86linux/helper.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GLIBC-style `syscall` hooking function.
 *
 * The input parameters are for the raw syscall instruction.
 * Do NOT use those with the original GLIBC's `syscall` wrapper function!
 *
 * Save `0` to `*forward` to prevent forwarding of the original syscall to the
 * kernel. (`*forward` is initially `1`)
 *
 * Intercepting the following system calls (and processing them directly) can
 * result in infinite loops (and break liboverlaysys) as they will always be
 * emulated for liboverlaysys's internal use: `exit`, `exit_group`,
 * `rt_sigaction` and `sigaltstack`.
 *
 * For interception:
 * Upon error, save appropriate `errno` value to it and return `-1` like you
 * usually do within the user space applications.
 */
extern long (*overlaysys_syscall_hook)(long number, long a, long b, long c,
                                       long d, long e, long f,
                                       int *restrict forward) __nonnull((8));

/*
 * Signal handler hooking function.
 *
 * `orig_handler` contains the address of the original signal handler function
 * enabled at this signal arrival. You can use this optionally to run the
 * original handler before or during your custom signal interception routine.
 *
 * Save `0` to `*forward` to prevent forwarding of the signal to the original
 * signal handler. (`*forward` is initially `1`)
 */
extern void (*overlaysys_signal_hook)(int sig, siginfo_t *info, void *ucontext,
                                      void (*orig_handler)(int, siginfo_t *,
                                                           void *),
                                      int *restrict forward)
    __nonnull((2, 3, 4, 5));

/* Child-side post-`clone*` hook. */
extern void *(*overlaysys_clone_callback_child)();
/*
 * Parent-side post-`clone*` hook.
 *
 * The `child_tid` is the TID of the newly created child process/thread.
 */
extern void (*overlaysys_clone_callback_parent)(pid_t child_tid);

/*
 * Raw syscall wrapper function.
 *
 * It behaves like GLIBC's `syscall` for return value or `errno` handling while
 * treating the arguments as for the raw syscall instruction.
 */
long overlaysys_syscall(long number, ...);

/*
 * Return `1` if liboverlaysys is allowed to be initialized to function for this
 * execution. Currently, it is not permitted to be active when either
 * `syscall_hook_in_process_allowed` from libsyscall_intercept returns false or
 * it detects Clang's AddressSanitizer.
 *
 * ANY interception should not be done in control flow where this returns `0`.
 * For example, fault happens due to the interception logic itself where this
 * evaluates to `0`, other fault handling preloaded tools like Valgrind or
 * AddressSanitizer (specially Clang's one) will break.
 */
int overlaysys_is_allowed();

void overlaysys_enable_syscall_wrapper();
void overlaysys_disable_syscall_wrapper();

pid_t overlaysys_get_tid();
size_t overlaysys_get_nr_main_thread();

#ifdef __cplusplus
}
#endif
