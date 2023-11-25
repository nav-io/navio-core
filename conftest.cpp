/* confdefs.h */
#define PACKAGE_NAME "Navcoin Core"
#define PACKAGE_TARNAME "navcoin"
#define PACKAGE_VERSION "25.99.0"
#define PACKAGE_STRING "Navcoin Core 25.99.0"
#define PACKAGE_BUGREPORT "https://github.com/navcoin/navcoin/issues"
#define PACKAGE_URL "https://navcoin.org/"
#define HAVE_CXX17 1
#define HAVE_STDIO_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STRING_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_STDINT_H 1
#define HAVE_STRINGS_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_UNISTD_H 1
#define STDC_HEADERS 1
#define HAVE_DLFCN_H 1
#define LT_OBJDIR ".libs/"
#define USE_ASM 1
#define ENABLE_ARM_SHANI 1
#define HAVE_PTHREAD_PRIO_INHERIT 1
#define HAVE_PTHREAD 1
#define HAVE_DECL_STRERROR_R 1
#define HAVE_STRERROR_R 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_SYSCTL_H 1
#define HAVE_SYS_VMMETER_H 1
#define HAVE_DECL_GETIFADDRS 1
#define HAVE_DECL_FREEIFADDRS 1
#define HAVE_DECL_FORK 1
#define HAVE_DECL_SETSID 1
#define HAVE_DECL_PIPE2 0
#define HAVE_TIMINGSAFE_BCMP 1
#define HAVE_DECL_LE16TOH 0
#define HAVE_DECL_LE32TOH 0
#define HAVE_DECL_LE64TOH 0
#define HAVE_DECL_HTOLE16 0
#define HAVE_DECL_HTOLE32 0
#define HAVE_DECL_HTOLE64 0
#define HAVE_DECL_BE16TOH 0
#define HAVE_DECL_BE32TOH 0
#define HAVE_DECL_BE64TOH 0
#define HAVE_DECL_HTOBE16 0
#define HAVE_DECL_HTOBE32 0
#define HAVE_DECL_HTOBE64 0
#define HAVE_DECL_BSWAP_16 0
#define HAVE_DECL_BSWAP_32 0
#define HAVE_DECL_BSWAP_64 0
#define HAVE_BUILTIN_CLZL 1
#define HAVE_BUILTIN_CLZLL 1
#define HAVE_DEFAULT_VISIBILITY_ATTRIBUTE 1
#define HAVE_THREAD_LOCAL 1
#define HAVE_GMTIME_R 1
#define HAVE_GETENTROPY_RAND 1
#define HAVE_SYSCTL 1
#define HAVE_FDATASYNC 0
#define HAVE_O_CLOEXEC 1
#define HAVE_SYSTEM 1
#define HAVE_BUILTIN_MUL_OVERFLOW 1
/* end confdefs.h.  */

        #include <libdb5.3/db_cxx.h>

int
main (void)
{

        #if !((DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 8) || DB_VERSION_MAJOR > 4)
          #error "failed to find bdb 4.8+"
        #endif

  ;
  return 0;
}
