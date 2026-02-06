#include "sicode_np.h"

#include <x86linux/helper.h>

__attribute((const)) const char *sicode_np(int sig, int si_code) {
  const char *cstrp = NULL;

  switch (sig) {
  case SIGILL:
    switch (si_code) {
    case ILL_ILLOPC:
      cstrp = "ILL_ILLOPC";
      break;
    case ILL_ILLOPN:
      cstrp = "ILL_ILLOPN";
      break;
    case ILL_ILLADR:
      cstrp = "ILL_ILLADR";
      break;
    case ILL_ILLTRP:
      cstrp = "ILL_ILLTRP";
      break;
    case ILL_PRVOPC:
      cstrp = "ILL_PRVOPC";
      break;
    case ILL_PRVREG:
      cstrp = "ILL_PRVREG";
      break;
    case ILL_COPROC:
      cstrp = "ILL_COPROC";
      break;
    case ILL_BADSTK:
      cstrp = "ILL_BADSTK";
      break;
    case ILL_BADIADDR:
      cstrp = "ILL_BADIADDR";
      break;
    }
    break;

  case SIGFPE:
    switch (si_code) {
    case FPE_INTDIV:
      cstrp = "FPE_INTDIV";
      break;
    case FPE_INTOVF:
      cstrp = "FPE_INTOVF";
      break;
    case FPE_FLTDIV:
      cstrp = "FPE_FLTDIV";
      break;
    case FPE_FLTOVF:
      cstrp = "FPE_FLTOVF";
      break;
    case FPE_FLTUND:
      cstrp = "FPE_FLTUND";
      break;
    case FPE_FLTRES:
      cstrp = "FPE_FLTRES";
      break;
    case FPE_FLTINV:
      cstrp = "FPE_FLTINV";
      break;
    case FPE_FLTSUB:
      cstrp = "FPE_FLTSUB";
      break;
    case FPE_FLTUNK:
      cstrp = "FPE_FLTUNK";
      break;
    case FPE_CONDTRAP:
      cstrp = "FPE_CONDTRAP";
      break;
    }
    break;

  case SIGSEGV:
    switch (si_code) {
    case SEGV_MAPERR:
      cstrp = "SEGV_MAPERR";
      break;
    case SEGV_ACCERR:
      cstrp = "SEGV_ACCERR";
      break;
    case SEGV_BNDERR:
      cstrp = "SEGV_BNDERR";
      break;
    case SEGV_PKUERR:
      cstrp = "SEGV_PKUERR";
      break;
    case SEGV_ACCADI:
      cstrp = "SEGV_ACCADI";
      break;
    case SEGV_ADIDERR:
      cstrp = "SEGV_ADIDERR";
      break;
    case SEGV_ADIPERR:
      cstrp = "SEGV_ADIPERR";
      break;
    case SEGV_MTEAERR:
      cstrp = "SEGV_MTEAERR";
      break;
    case SEGV_MTESERR:
      cstrp = "SEGV_MTESERR";
      break;
    case SEGV_CPERR:
      cstrp = "SEGV_CPERR";
      break;
    }
    break;

  case SIGBUS:
    switch (si_code) {
    case BUS_ADRALN:
      cstrp = "BUS_ADRALN";
      break;
    case BUS_ADRERR:
      cstrp = "BUS_ADRERR";
      break;
    case BUS_OBJERR:
      cstrp = "BUS_OBJERR";
      break;
    case BUS_MCEERR_AR:
      cstrp = "BUS_MCEERR_AR";
      break;
    case BUS_MCEERR_AO:
      cstrp = "BUS_MCEERR_AO";
      break;
    }
    break;

  case SIGTRAP:
    switch (si_code) {
    case TRAP_BRKPT:
      cstrp = "TRAP_BRKPT";
      break;
    case TRAP_TRACE:
      cstrp = "TRAP_TRACE";
      break;
    case TRAP_BRANCH:
      cstrp = "TRAP_BRANCH";
      break;
    case TRAP_HWBKPT:
      cstrp = "TRAP_HWBKPT";
      break;
    case TRAP_UNK:
      cstrp = "TRAP_UNK";
      break;
    }
    break;

  case SIGCHLD:
    switch (si_code) {
    case CLD_EXITED:
      cstrp = "CLD_EXITED";
      break;
    case CLD_KILLED:
      cstrp = "CLD_KILLED";
      break;
    case CLD_DUMPED:
      cstrp = "CLD_DUMPED";
      break;
    case CLD_TRAPPED:
      cstrp = "CLD_TRAPPED";
      break;
    case CLD_STOPPED:
      cstrp = "CLD_STOPPED";
      break;
    case CLD_CONTINUED:
      cstrp = "CLD_CONTINUED";
      break;
    }
    break;

  case SIGPOLL:
    switch (si_code) {
    case POLL_IN:
      cstrp = "POLL_IN";
      break;
    case POLL_OUT:
      cstrp = "POLL_OUT";
      break;
    case POLL_MSG:
      cstrp = "POLL_MSG";
      break;
    case POLL_ERR:
      cstrp = "POLL_ERR";
      break;
    case POLL_PRI:
      cstrp = "POLL_PRI";
      break;
    case POLL_HUP:
      cstrp = "POLL_HUP";
      break;
    }
    break;
  }

  if (likely(!cstrp))
    switch (si_code) {
    case SI_ASYNCNL:
      cstrp = "SI_ASYNCNL";
      break;
    case SI_DETHREAD:
      cstrp = "SI_DETHREAD";
      break;
    case SI_TKILL:
      cstrp = "SI_TKILL";
      break;
    case SI_SIGIO:
      cstrp = "SI_SIGIO";
      break;
    case SI_ASYNCIO:
      cstrp = "SI_ASYNCIO";
      break;
    case SI_MESGQ:
      cstrp = "SI_MESGQ";
      break;
    case SI_TIMER:
      cstrp = "SI_TIMER";
      break;
    case SI_QUEUE:
      cstrp = "SI_QUEUE";
      break;
    case SI_USER:
      cstrp = "SI_USER";
      break;
    case SI_KERNEL:
      cstrp = "SI_KERNEL";
      break;
    }

  return cstrp;
}
