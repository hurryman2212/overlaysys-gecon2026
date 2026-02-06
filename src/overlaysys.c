#include "overlaysys.h"

#include "sicode_np.h"

#include <string.h>

#include <dlfcn.h>
#include <ucontext.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#include <backtrace.h>

#include <libsyscall_intercept_hook_point.h>

#include <x86linux/helper.h>

/* Definitions to handle environment variables. */

enum {
  NODEFSIGHAND,
  USEDEFSIGHAND,
  OVERWRITEDEFSIGHAND,
  FORCEDEFSIGHAND,
};

/* Variable to enable omissible options. */
static int enable_defsighand, enable_sigaltstackautodisarm,
    enable_sigaltstackeperm;

/* `size_t` value to set the default signal alternate stack size. */
static size_t enable_defsigaltstack;

/* Setup static variables with environment variables. */
static void init_env() {
  const char *const _env_defsighand = getenv("OVERLAYSYS_DEFSIGHAND");
  if (unlikely(_env_defsighand))
    log_verify_error(enable_defsighand = strtol(_env_defsighand, NULL, 0));

  enable_sigaltstackautodisarm = !!getenv("OVERLAYSYS_SIGALTSTACKAUTODISARM");
  enable_sigaltstackeperm = !!getenv("OVERLAYSYS_SIGALTSTACKEPERM");

  const char *const _env_defsigaltstack = getenv("OVERLAYSYS_DEFSIGALTSTACK");
  if (unlikely(_env_defsigaltstack)) {
    log_verify_error(enable_defsigaltstack =
                         strtoul(_env_defsigaltstack, NULL, 0));

    const long _minsigstksz =
        log_call(LOG_DEBUG, "%ld", sysconf, "%d (_SC_SIGSTKSZ)", _SC_SIGSTKSZ);
    log_verify(_minsigstksz != -1 &&
               enable_defsigaltstack >= (size_t)_minsigstksz);
  }
}

/*
 * Static TLS variables.
 *
 * Their values will not be inherited when the thread holding it is created with
 * TLS reinitialization (see `man 2 clone`); In this case, the values will be
 * reverted to their compile-time initial values. `fork` and `vfork` system
 * calls do not reinitialize TLS so their values will be inherited (although
 * `vfork is still problematic; see the below and `man 2 vfork`).
 *
 * Using `CLONE_VM` flag without `CLONE_SETTLS` or using `CLONE_VFORK` (or using
 * `vfork` system call of which effect is like `CLONE_VFORK` plus `CLONE_VM`
 * without `CLONE_SETTLS`) will invalidate the further usage of TLS variables as
 * their writes will be overlapped with other threads sharing them.
 */

/*
 * The TLS variable for storing the start virtual address of memory range mapped
 * for our default signal alternate stack.
 *
 * Please refer to the explanation regarding TLS variables in this file.
 *
 * The signal alternate stack setting including the start virtual address for
 * the new thread will be inherited except the case when it is `clone*`-ed with
 * `CLONE_VM` flag WITHOUT `CLONE_VFORK`, or forked by `vfork`, although `vfork`
 * suspends the parent before `exit` or `exec*` system calls (see `man 2
 * vfork`). If it does not share the virtual memory mapping (i.e. no `CLONE_VM`
 * used), this pointer value (virtual address to the signal alternate stack
 * memory) will be the same as the parent but does not share the actual mapping
 * (as any sane person will allocate memory for this with `MAP_PRIVATE` flag).
 *
 * Currently, libsyscall_intercept does not invoke post-`clone*` handlers for
 * `vfork`. If it does, there should be logic implemented to distinguish
 * `vfork`-ed threads to prevent the deallocation of the signal alternate stack
 * memory with the conditional variable set by the child-side post-`clone*`
 * handler, or there will be segmentation fault in the parent side when it
 * resumes and a signal is delivered to it.
 */
static thread_local __attribute((tls_model("initial-exec"))) void *defsigstk;

typedef struct {
  unsigned long __val[(NSIG - 1) / (8 * sizeof(unsigned long))]; // ?
} kernel_sigset_t;
/*
 * The temporal TLS variable for storing the original signal mask.
 *
 * Please refer to the explanation regarding TLS variables in this file.
 */
static thread_local
    __attribute((tls_model("initial-exec"))) kernel_sigset_t oset;

static thread_local __attribute((tls_model("initial-exec"))) pid_t tid;

/* Definitions for kernel-specific signal handling. */

static __always_inline int
raw_rt_sigprocmask(int signum, const kernel_sigset_t *restrict set,
                   kernel_sigset_t *restrict oldset) {
  return syscall_no_intercept(SYS_rt_sigprocmask, signum, set, oldset,
                              sizeof(kernel_sigset_t));
}

/*
 * Do not create a thread within AS-safe critical section!
 *
 * Since `oset` is a TLS variable, its value may not be inherited when the
 * thread is created with TLS reinitialization (see the explanation regarding
 * TLS variables in this file) so that the restoration of signal mask setting
 * (which is always inherited) will not be done properly (and don't forget the
 * fact that the inherited signal mask covers all signals at that point). Use
 * `pthread_attr_setsigmask_np` to pre-set the signal mask for the new thread
 * (see `man 3 pthread_attr_setsigmask_np`; it calls `sigprocmask` after its
 * creation) when using `pthread_create`.
 *
 * The difference between `pthread_sigmask` and `sigprocmask` wrapper function
 * is that the former defines the multithreaded usage in the specification (see
 * `man 3 pthread_sigmask`), but the implementation
 * (https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=nptl/pthread_sigmask.c)
 * of it is just calling it with different style in returning error code (and
 * clearing internal signals for the NPTL implementation).
 */

static const kernel_sigset_t fset = {
    .__val = {[0 ... sizeof_elem(fset, __val) / sizeof_elem(fset, __val, *) -
               1] = (typeof_elem(fset, __val, *))UINT64_MAX}};
#define AS_ENTER()                                                             \
  log_verify(!syscall_error_code(raw_rt_sigprocmask(SIG_SETMASK, &fset, &oset)))
#define AS_EXIT()                                                              \
  log_verify(!syscall_error_code(raw_rt_sigprocmask(SIG_SETMASK, &oset, NULL)))

struct kernel_sigaction { // See `asm/signal.h`.
  union {
    void (*_kernel_sa_handler)(int);
#define kernel_sa_handler sigaction_handler._kernel_sa_handler
    void (*_kernel_sa_sigaction)(int, siginfo_t *, void *);
#define kernel_sa_sigaction sigaction_handler._kernel_sa_sigaction
  } sigaction_handler;
  unsigned long sa_flags;
  void (*sa_restorer)();
  kernel_sigset_t sa_mask;
};
static __always_inline int
raw_rt_sigaction(int signum, const struct kernel_sigaction *restrict kact,
                 struct kernel_sigaction *restrict oldkact) {
  return syscall_no_intercept(SYS_rt_sigaction, signum, kact, oldkact,
                              sizeof(kernel_sigset_t));
}

#define SS_AUTODISARM (1U << 31) // See `linux/signal.h`.

/*
 * Enum for specifiying types of signal default dispositions (actions or
 * behaviors); See `man 7 signal`.
 */
enum {
  Term,
  Ign,
  Core,
  Stop,
  Cont,
};
/* Return -1 and set `errno` to `EINVAL` when `sig` is invalid. */
static __attribute((const)) int sigdef(int sig) {
  /* See `man 7 signal`. */
  switch (sig) {
  case SIGALRM:
  // case SIGEMT: // (not defined)
  case SIGHUP:
  case SIGINT:
  case SIGIO:
    static_assert(SIGIO == SIGPOLL);
  case SIGKILL:
  // case SIGLOST: // (not defined; unused by default)
  case SIGPIPE:
  case SIGPROF:
  case SIGPWR:
    // static_assert(SIGPWR == SIGINFO); // (SIGINFO is not defined)
  case SIGSTKFLT: // (unused by default)
  case SIGTERM:
  case SIGUSR1:
  case SIGUSR2:
  case SIGVTALRM:
    return Term;

  case SIGCHLD:
    static_assert(SIGCHLD == SIGCLD);
  case SIGURG:
  case SIGWINCH:
    return Ign;

  case SIGABRT:
    static_assert(SIGABRT == SIGIOT);
  case SIGBUS:
  case SIGFPE:
  case SIGILL:
  case SIGQUIT:
  case SIGSEGV:
  case SIGSYS:
    // static_assert(SIGSYS == SIGUNUSED); // (SIGUNUSED is not defined)
  case SIGTRAP:
  case SIGXCPU:
  case SIGXFSZ:
    return Core;

  case SIGSTOP:
  case SIGTSTP:
  case SIGTTIN:
  case SIGTTOU:
    return Stop;

  case SIGCONT:
    return Cont;
  }

  return likely(sig >= SIGRTMIN && sig <= SIGRTMAX) ? Term : ({
    errno = EINVAL;
    -1;
  });
}

/* Syscall interception. */

static __always_inline void *raw_mmap(void *addr, size_t length, int prot,
                                      int flags, int fd, off64_t offset) {
  return (void *)syscall_no_intercept(SYS_mmap, addr, length, prot, flags, fd,
                                      offset);
}
static __always_inline int raw_munmap(void *addr, size_t length) {
  return syscall_no_intercept(SYS_munmap, addr, length);
}

static __always_inline int raw_sigaltstack(const stack_t *restrict ss,
                                           stack_t *restrict old_ss) {
  return syscall_no_intercept(SYS_sigaltstack, ss, old_ss);
}

/*
 * Use this function carefully! (please refer to the explanation for the
 * `defsigstk` static variable)
 *
 * Also, it does not check whether `defsigstk` is `NULL` or not.
 */
static void unmap_defsigstk() {
  log_verify(!syscall_error_code(raw_munmap(defsigstk, enable_defsigaltstack)));

  defsigstk = NULL;
}

static int emulate_sigaltstack(const stack_t *restrict ss,
                               stack_t *restrict old_ss) {
  if (unlikely(enable_sigaltstackeperm)) {
    errno = EPERM;
    return -1;
  }

  /*
   * Currently, we do not prevent the original code to disable existing signal
   * alternate stack even if ours is the installed one.
   */
  const int _raw_ret = raw_sigaltstack(ss, old_ss);
  if (unlikely(defsigstk) && ss && likely(!syscall_error_code(_raw_ret)))
    /*
     * Optimization: Do not enter AS-safe critical section to unmap the previous
     * default signal alternate stack here.
     *
     * The memory range pointed by `defsigstk` is exclusively used by our main
     * interception library, which is only set during the thread creation. Since
     * the signal stack setting is already changed at this point (see `man 2
     * sigaltstack`), this dynamic memory range will not be used both
     * synchronously and asynchronously.
     */
    unmap_defsigstk();

  return _raw_ret;
}

/* This should only be called after `init_defsigaltstack` in each thread. */
static unsigned long get_default_sa_flags() {
  return SA_SIGINFO | (unlikely(defsigstk) ? SA_ONSTACK : 0);
}
/*
 * All local threads share the same `sigaction`; See `man 2 clone` about
 * `CLONE_SIGHAND`, `CLONE_VM` and `CLONE_THREAD`.
 *
 * Currently, we do not save `sa_mask` and `sa_restorer` as they are not used
 * within our interception library.
 */
static struct {
  typeof_elem(struct kernel_sigaction, sigaction_handler) sigaction_handler;
  typeof_elem(struct kernel_sigaction, sa_flags) sa_flags;
} orig_ksa[NSIG]; // Index `0` is never used in this array.
static void sighand_wrapper(int, siginfo_t *, void *);
static uint32_t rt_sigaction_lock;
static int emulate_rt_sigaction(int signum,
                                const struct kernel_sigaction *restrict kact,
                                struct kernel_sigaction *restrict oldkact,
                                size_t sigsetsize) {
  trace_assert(sigsetsize == sizeof(kernel_sigset_t));

  int _should_intercept = 0;
  struct kernel_sigaction _ksa;
  if (kact) {
    /*
     * Override values in `kact` to install our signal handler wrapper when:
     * 1. `kact` holds an user-defined signal handler.
     * 2. `enable_defsighand` is true and the signal type is `Core` or `Term`.
     */

    _should_intercept = (kact->kernel_sa_handler != SIG_DFL &&
                         kact->kernel_sa_handler != SIG_IGN);
    if (unlikely(enable_defsighand) && !_should_intercept &&
        kact->kernel_sa_handler == SIG_DFL) {
      const int _def = sigdef(signum);
      _should_intercept = _def == Core || _def == Term;
    }
    if (_should_intercept) {
      _ksa.kernel_sa_sigaction = sighand_wrapper;
      _ksa.sa_flags = kact->sa_flags | get_default_sa_flags();

      _ksa.sa_restorer = kact->sa_restorer;

      /* Should we use `__builtin_*` version? */
      __builtin_memcpy(&_ksa.sa_mask, &kact->sa_mask, sizeof(kernel_sigset_t));
    }
  }

  log_verify_error(usersched_plock_pi2(
      &rt_sigaction_lock, tid,
      USERSCHED_RESTART | USERSCHED_NOEAGAIN | FUTEX_PRIVATE_FLAG,
      100 * usersched_tsc_1us, NULL, NULL, NULL));

  const int _raw_ret =
      raw_rt_sigaction(signum, _should_intercept ? &_ksa : kact, oldkact);
  if (likely(!syscall_error_code(_raw_ret))) {
    if (oldkact) {
      /* Overwrite the old `struct sigaction` set by the kernel. */
      oldkact->kernel_sa_sigaction = orig_ksa[signum].kernel_sa_sigaction;
      oldkact->sa_flags = orig_ksa[signum].sa_flags;
    }

    if (kact) {
      /* Save the input `struct sigaction` as the original. */
      orig_ksa[signum].kernel_sa_sigaction = kact->kernel_sa_sigaction;
      orig_ksa[signum].sa_flags = kact->sa_flags;
    }
  }

  log_verify_error(
      usersched_punlock_pi(&rt_sigaction_lock, tid, FUTEX_PRIVATE_FLAG,
                           NULL)); // This includes full memory barrier.

  return _raw_ret;
}

static size_t nr_main_thread;
static int emulate_exit(int status) {
  /* TODO: `vfork` handling. (see the comment about `defsigstk`) */

  /*
   * If `defsigstk` is non-`NULL`, it means this is a thread that has allocated
   * a memory range for its default signal alternate stack. So upon the (normal)
   * termination of this thread should unmap it.
   */
  if (unlikely(defsigstk)) {
    AS_ENTER(); // Prevent signal arrival to this thread.

    unmap_defsigstk();

    /*
     * Optimization: Do not exit the AS-safe critical section as it will be
     * terminated by the subsequent `exit` system call anyway.
     */
  }

  /* This will always succeed. */
  return syscall_no_intercept(SYS_exit, status);
}

static int emulate_syscall(long number, long a, long b, long c, long d, long e,
                           long f, long *restrict res);
static int within_hook() {
  /* It also handles the case when the TLS variable is not yet initialized. */
  return intercept_hook_point == emulate_syscall ? 1 : 0;
}
static int emulate_syscall(long number, long a, long b, long c, long d, long e,
                           long f, long *restrict res) {
  switch (number) {
  case SYS_exit:
    *res = emulate_exit(a);
    break;

    /*
     * `exit_group` terminates all threads in the same thread group, so we do
     * not need to check and unmap our default signal alternate stack for this
     * thread and thread group.
     *
     * No need to decrease the number of threads in the thread group too as this
     * either fails or terminates the whole thread group.
     */

  case SYS_rt_sigaction:
    *res = emulate_rt_sigaction(a, address_cast(b), address_cast(c), d);
    break;

  case SYS_sigaltstack:
    *res = emulate_sigaltstack(address_cast(a), address_cast(b));
    break;

  default:
    return 1;
  }
  return 0;
}

static void disable_syscall_wrapper() {
  intercept_hook_point = emulate_syscall;
}
static int syscall_wrapper(long, long, long, long, long, long, long, long *);
static void enable_syscall_wrapper() { intercept_hook_point = syscall_wrapper; }
static int syscall_wrapper(long number, long a, long b, long c, long d, long e,
                           long f, long *restrict res) {
  /*
   * Intercept the syscall and save the return value to `*result`.
   *
   * Return 0 to prohibit the original syscall from forwarding to the kernel.
   */

  /* Disable syscall interception. */
  disable_syscall_wrapper();

  int _forward = 1;
  long (*const _syscall_hook)(long, long, long, long, long, long, long, int *) =
      overlaysys_syscall_hook;
  if (_syscall_hook) {
    const long _c_ret = _syscall_hook(number, a, b, c, d, e, f, &_forward);
    *res = unlikely(_c_ret == -1) ? -errno : _c_ret;
  }

  if (_forward)
    _forward = emulate_syscall(number, a, b, c, d, e, f, res);

  /* Enable syscall interception again. */
  enable_syscall_wrapper();

  return _forward;
}

/* Signal interception. */

static int print_addr2line(void *restrict data, uintptr_t pc,
                           const char *restrict filepath, int line,
                           const char *restrict func) {
  const Dl_info *const restrict _info = data;
  log(LOG_EMERG, "at 0x%lx: %s [%p] (%s:%d)", pc, func, _info->dli_saddr,
      filename(filepath), line);
  return 0;
}
static void defsighand(int sig, const siginfo_t *restrict info,
                       const void *restrict context) {
  const ucontext_t *const restrict _u = context;
  const long long _pc = _u->uc_mcontext.gregs[REG_RIP];

  Dl_info _info;
  dladdr(address_cast(_pc), &_info);
  const int si_code = info->si_code;
  log(LOG_EMERG,
      "--- SIG%s (%s) {si_code=%d (%s), si_errno=%d, dli_fname=%s, "
      "dli_fbase=%p} ---",
      sigabbrev_np(sig), sigdescr_np(sig), si_code, sicode_np(sig, si_code),
      info->si_errno, _info.dli_fname, _info.dli_fbase);

  struct backtrace_state *const restrict _state =
      backtrace_create_state(NULL, 0, NULL, NULL);
  backtrace_pcinfo(_state, _pc, print_addr2line, NULL, &_info);

  log_backtrace(LOG_EMERG);
}

static void sighand_wrapper(int sig, siginfo_t *info, void *context) {
  void (*const _orig_handler)(int, siginfo_t *, void *) =
      orig_ksa[sig].kernel_sa_sigaction;
  /*
   * We only access the word-size function pointer value, referring the original
   * signal handler, within the saved `struct sigaction`.
   *
   * This "weakly" ensures the order of signal handlers to be called when it can
   * be changed by `sigaction`.
   */

  const int _within_hook = within_hook();

  /* Disable syscall interception. */
  disable_syscall_wrapper();

  int _forward = 1;
  void (*const _signal_hook)(int, siginfo_t *, void *,
                             void (*)(int, siginfo_t *, void *), int *) =
      overlaysys_signal_hook;
  if (_signal_hook)
    _signal_hook(sig, info, context, _orig_handler, &_forward);

  if (_forward) {
    if (likely(
            _orig_handler)) { // Optimization for signal-based asynchronous I/O.
      enable_syscall_wrapper();

      /*
       * Entering the original signal handler will finally notice the original
       * program a notion of signal generated. This "weakly" ensures the correct
       * behavior when using `SA_NODEFER` and changing the signal setting of the
       * same signal concurrently by the signal handler or another thread in the
       * same thread group.
       *
       * Even if the signal handler calls `setcontext`, `swapcontext` or
       * `*longjmp`, syscall interception is already enabled so it's OK.
       */
      _orig_handler(sig, info, context);

      disable_syscall_wrapper();
    } else {
      /*
       * The user has not set a signal handler for this; Use the default one.
       *
       * Installing our signal handler wrapper by default for all signal types
       * will invalidate correct behavior when handling `ERESTARTNOHAND`.
       *
       * This path should only be used when our default signal handler is
       * enabled and the signal type is either `Core` or `Term`.
       */

      defsighand(sig, info, context);

      /* Prepare to forward it to the kernel again, without interception. */
      struct kernel_sigaction _ksa = {.kernel_sa_handler = SIG_DFL,
                                      .sa_flags = 0,
                                      .sa_restorer = NULL,
                                      .sa_mask = {0}};
      log_verify(!syscall_error_code(raw_rt_sigaction(sig, &_ksa, NULL)));

      log_verify_error(setcontext(context)); // ?
    }
  }

  /* Enable syscall interception again (if required). */
  if (!_within_hook)
    enable_syscall_wrapper();
}

/*
 * This function should only be called when initializing a new thread; Note that
 * the signal alternate stack must be unmapped when the thread is terminated.
 *
 * Process-wide termination due to terminating signals is not a concern here
 * because the memory range for the stack is per-procee resource (if we use a
 * `MAP_PRIVATE`-type mapping method for it, which is obvious).
 */
static void init_defsigaltstack() {
  /*
   * Check whether previous invocation of user-defined signal handler has
   * already installed its signal atlernat stack.
   *
   * Since the signal invocation on this thread, calling an original user-space
   * signal handler or signal intercepting routine, may call `sigaltstack` (yes,
   * it can be called inside in signal handler context if there is no previous
   * one installed for the thread) to change the signal alternate stack, it is
   * not enough to check the flags used in the previous `clone*` call (see `man
   * 2 clone`) on the backend hotpatching library.
   */

  AS_ENTER();

  stack_t _oss;
  log_verify(!syscall_error_code(raw_sigaltstack(NULL, &_oss)));

  /*
   * Check if ANY signal alternate stack is currently disabled on the thread; Do
   * not overwrite an existing one whether it is from the original code or ours.
   */
  if (_oss.ss_flags == SS_DISABLE) {
    const size_t _size = enable_defsigaltstack;
    log_verify(!syscall_error_code(
        (long)(defsigstk = raw_mmap(NULL, _size, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))));

    const stack_t _ss = {
        .ss_size = _size,
        .ss_sp = defsigstk,

        /* Programs like Valgrind do not accept `SS_AUTODISARM`. */
        .ss_flags = unlikely(enable_sigaltstackautodisarm) ? SS_AUTODISARM : 0,
    };
    log_verify(!syscall_error_code(raw_sigaltstack(&_ss, NULL)));
  }

  AS_EXIT();
}

/* `clone*` wrappers. */

static void clone_wrapper_child() {
  /* TODO: `vfork` handling. (see the comment about `defsigstk`) */

  /*
   * Due to the current limitation of the backend hotpatching library, it is not
   * able to intercept `fork` (the raw system call one (see `man 2 fork`);
   * `fork` system call wrapper from GLIBC uses `clone*` inside to implement
   * `pthread_atfork`), or `vfork`.
   *
   * The raw `clone*` system call behaves like `fork` and `vfork` system call as
   * it returns to the original control flow even in the child thread (see `man
   * 2 clone`). This is the reason why the backend hotpatching library can
   * intercept it even in the child side.
   *
   * It is possibly the non-AS-safe section where `intercept_hook_point` might
   * be `NULL` if the TLS variable is initialized in the new thread. Thus
   * calling this function for newly created threads with its TLS region
   * reinitialized is required, even for those created in the interceptions.
   */

  const int _within_hook = within_hook();
  disable_syscall_wrapper(); // This will fix the `NULL` TLS variable.

  tid = gettid();

  /*
   * Signal alternate stack is per-thread attribute so we need to reinstall a
   * new instance of it if required.
   */
  if (unlikely(enable_defsigaltstack))
    init_defsigaltstack();

  void *(*const _clone_callback_child)() = overlaysys_clone_callback_child;
  if (_clone_callback_child)
    _clone_callback_child();

  if (tid == getpid()) {
    /* A new thread group is created. */

    nr_main_thread = 1;
    /* No need to use memory barrier here. */
  } else
    /* This thread belongs to an existing thread group. */
    __sync_add_and_fetch(&nr_main_thread, 1);

  if (!_within_hook)
    enable_syscall_wrapper();
}

static void clone_wrapper_parent(long child_tid) {
  /*
   * Due to the current limitation of the backend hotpatching library, it is not
   * able to intercept `fork` (the raw system call one (see `man 2 fork`);
   * `fork` system call wrapper from GLIBC uses `clone*` inside to implement
   * `pthread_atfork`), or `vfork`.
   */

  void (*const _clone_callback_parent)(pid_t) =
      overlaysys_clone_callback_parent;
  if (_clone_callback_parent) {
    const int _within_hook = within_hook();
    disable_syscall_wrapper();

    _clone_callback_parent(child_tid);

    if (!_within_hook)
      enable_syscall_wrapper();
  }
}

/* Initialization. */

static int is_allowed() {
  /*
   * Support Clang-based code sanitizers: Check if the name of the current
   * program executed is `llvm-symbolizer*`.
   */
  const char *const _progname = program_invocation_short_name;
  return syscall_hook_in_process_allowed() &&
         strstr(_progname, "llvm-symbolizer") != _progname;
}

static void init_signal_wrapper() {
  /*
   * To support `ERESTARTNOHAND` properly, we cannot install our signal handler
   * by default, other than `Core` and `Term` type signals.
   */

  const int _sa_flags = get_default_sa_flags();

  const struct sigaction _sa = {
      .sa_sigaction = sighand_wrapper,
      .sa_mask = {0},
      .sa_flags = _sa_flags,
      .sa_restorer = NULL,
  };

  for (int i = 1; i < NSIG; ++i) {
    const int _def = sigdef(i);

    /* Be careful not to include non-interceptable signals. */
    if (likely(_def == Core || (_def == Term && i != SIGKILL))) {
      struct sigaction _osa;
      log_verify_error(sigaction(i, NULL, &_osa));

      /*
       * Facilities like Valgrind or Clang-based code sanitizers may
       * pre-install signal handlers or `SIG_IGN`.
       */
      if (unlikely(_osa.sa_sigaction) &&
          likely(enable_defsighand <= USEDEFSIGHAND)) {
        log(LOG_DEBUG, "sigaction(%d, ...): _osa.sa_sigaction: %p", i,
            _osa.sa_sigaction);
        continue;
      }

      /*
       * Programs like Valgrind may not allow to change signal settings. For
       * example, Valgrind does not allow changing the signal handler for
       * `SIGRTMAX`, and it installs `SIG_IGN` on it.
       */
      if (unlikely(sigaction(i, &_sa, NULL))) {
        log(LOG_EMERG, "sigaction(%d, ...): %s (%s)", i, strerrordesc_np(errno),
            strerrorname_np(errno));
        if (unlikely(enable_defsighand >= FORCEDEFSIGHAND))
          log_abort();
      } else {
        /*
         * Save the overwritten original signal handler settings.
         *
         * Otherwise, facilities like code sanitizers will not be able to print
         * debug information when faulting signal arrives.
         *
         * If the current action of the signal is `SIG_IGN`, ignore it and
         * enforce the default action for it.
         */
        static_assert(
            sizeof_elem(struct kernel_sigaction, kernel_sa_sigaction) >=
            sizeof_elem(struct sigaction, sa_sigaction));
        static_assert(SIG_DFL == NULL);
        orig_ksa[i].kernel_sa_sigaction =
            _osa.sa_handler != SIG_IGN ? _osa.sa_sigaction : NULL;

        static_assert(sizeof_elem(struct kernel_sigaction, sa_flags) >=
                      sizeof_elem(struct sigaction, sa_flags));
        orig_ksa[i].sa_flags = _osa.sa_flags;
      }
    }
  }
}
static __attribute((constructor)) void setup() {
  /* Do not initialize if overlaysys_is_active() returns 0. */
  if (is_allowed()) {
    /* Do not enable the system call emulation yet! */

    void *const handle = dlmopen(LM_ID_NEWLM, "libpthread.so.0", RTLD_LAZY);
    if (!handle) {
      log(LOG_ERR, "dlmopen: %s", dlerror());
      exit(EXIT_FAILURE);
    }

    tid = gettid();

    nr_main_thread = 1;

    /* Call dependency functions first. */
    usersched_init(0);

    /* Check environment variables. */
    init_env();

    /* Initialize (optional) signal alternate stack first. */
    if (unlikely(enable_defsigaltstack))
      init_defsigaltstack();

    /* Initialize (optional) signal interception. */
    if (unlikely(enable_defsighand))
      init_signal_wrapper();

    /* After enabling signal interception, enable clone() hooks. */
    intercept_hook_point_clone_child = clone_wrapper_child;
    intercept_hook_point_clone_parent = clone_wrapper_parent;

    /* Start syscall interception after handling initial shadow threading. */
    enable_syscall_wrapper();
  }

  /*
   * Fault happening outside of the control flow where `overlaysys_is_active`
   * returns 1 but still within the user space interception path will break
   * Clang's run-time code sanitizers (AddressSanitizer, MemorySanitizer and
   * ThreadSanitizer) and possibly more...
   */
}

/* Public variables. */

typeof(overlaysys_syscall_hook) overlaysys_syscall_hook;

typeof(overlaysys_signal_hook) overlaysys_signal_hook;

typeof(overlaysys_clone_callback_child) overlaysys_clone_callback_child;
typeof(overlaysys_clone_callback_parent) overlaysys_clone_callback_parent;

/* Public functions. */

long overlaysys_syscall(long number, ...) {
  va_list _ap;
  va_start(_ap, number);
  register long _raw_ret asm("rax") = number;
  const register long _a asm("rdi") = va_arg(_ap, long);
  const register long _b asm("rsi") = va_arg(_ap, long);
  const register long _c asm("rdx") = va_arg(_ap, long);
  const register long _d asm("r10") = va_arg(_ap, long); // originally `rcx`
  const register long _e asm("r8") = va_arg(_ap, long);
  const register long _f asm("r9") = va_arg(_ap, long);
  va_end(_ap);

  asm volatile("syscall"
               : "=a"(_raw_ret)
               : "0"(_raw_ret), "D"(_a), "S"(_b), "d"(_c), "r"(_d), "r"(_e),
                 "r"(_f)
               : "rcx", "r11", "memory" // Kernel clobers these.
  );
  /*
   * `asm volatile("" : : : "memory")` serves as a compiler barrier. Since the
   * arguments could be used as pointers, we do not want to reuse the leftover
   * in the registers or reorder the preceding instructions after `syscall`.
   */

  /* `errno` should only be set when the return value is `-1`. */
  const int _errno = syscall_error_code(_raw_ret);
  if (unlikely(_errno)) {
    errno = -_errno;
    return -1;
  }
  return _raw_ret;
}

int overlaysys_is_allowed() { return is_allowed(); }

void overlaysys_enable_syscall_wrapper() { enable_syscall_wrapper(); }
void overlaysys_disable_syscall_wrapper() { disable_syscall_wrapper(); }

pid_t overlaysys_get_tid() { return tid; }
size_t overlaysys_get_nr_main_thread() { return nr_main_thread; }
