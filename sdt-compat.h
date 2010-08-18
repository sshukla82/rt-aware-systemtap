/* Copyright (C) 2005-2010 Red Hat Inc.

   This file is part of systemtap, and is free software in the public domain.
*/

#ifndef _SYS_SDT_H
#define _SYS_SDT_H    1

#include <string.h>
#include <sys/types.h>
#include <errno.h>


#define UPROBE1_TYPE 0x31425250 /* "PRB1" (little-endian) */
#define KPROBE1_TYPE 0x32425250 /* "PRB2" */
#define UPROBE2_TYPE 0x32425055 /* "UPB2" */
#define KPROBE2_TYPE 0x3242504b /* "KPB2" */

typedef enum
  {
    uprobe1_type = UPROBE1_TYPE,
    kprobe1_type = KPROBE1_TYPE,
    uprobe2_type = UPROBE2_TYPE,
    kprobe2_type = KPROBE2_TYPE 
  } stap_sdt_probe_type;

typedef struct 
{
  __uint32_t type_a;
  __uint32_t type_b;
  __uint64_t name;
  __uint64_t arg;
}  stap_sdt_probe_entry_v1;

typedef struct
{
  __uint32_t type_a;
  __uint32_t type_b;
  __uint64_t name;
  __uint64_t provider;
  __uint64_t arg_count;
  __uint64_t arg_string;
  __uint64_t pc;
  __uint64_t semaphore;
}   stap_sdt_probe_entry_v2;

#ifdef __LP64__
 #define STAP_PROBE_ADDR(arg) "\t.quad " arg
#elif defined (__BIG_ENDIAN__)
 #define STAP_PROBE_ADDR(arg) "\t.long 0\n\t.long " arg
#else
 #define STAP_PROBE_ADDR(arg) "\t.long " arg
#endif

/* Allocated section needs to be writable when creating pic shared objects
   because we store relocatable addresses in them.  We used to make this
   read only for non-pic executables, but the new semaphore support relies
   on having a writable .probes section to put the enabled variables in. */
#define ALLOCSEC "\"aw\""

#if ! defined EXPERIMENTAL_KPROBE_SDT

/* An allocated section .probes that holds the probe names and addrs. */
#if defined STAP_SDT_V1
 #define STAP_UPROBE_GUARD UPROBE1_TYPE
 #define STAP_TYPE(t) __typeof__((t))
 #define STAP_CAST(t) t
 #define STAP_PROBE_DATA_(provider,probe,guard,arg,arg_format,args,semaphore)	\
  __asm__ volatile (".section .probes," ALLOCSEC "\n"	\
		    "\t.balign 8\n"			\
		    "1:\n\t.asciz " #probe "\n"         \
		    "\t.balign 4\n"                     \
		    "\t.int " #guard "\n"		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR("1b\n")             \
		    "\t.balign 8\n"                     \
		    STAP_PROBE_ADDR(#arg "\n")		\
		    "\t.int 0\n"			\
		    "\t.previous\n")
#elif defined STAP_SDT_V2 || ! defined STAP_SDT_V1
 #define STAP_UPROBE_GUARD UPROBE2_TYPE
 #define STAP_TYPE(t) size_t
 #define STAP_CAST(t) (size_t)t
 #define STAP_PROBE_DATA_(provider,probe,guard,argc,arg_format,args,semaphore)	\
  __asm__ volatile (".section .probes," ALLOCSEC "\n"	\
  		    "\t.balign 8\n"			\
		    "\t.int " #guard "\n"		\
		    "\t.balign 8\n"			\
  		    STAP_PROBE_ADDR ("1f\n")		\
		    "\t.balign 8\n"			\
  		    STAP_PROBE_ADDR ("2f\n")		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR (#argc "\n")	\
                    "\t.balign 8\n"                     \
                    STAP_PROBE_ADDR("3f\n")		\
                    "\t.balign 8\n"                     \
                    STAP_PROBE_ADDR("4f\n")          	\
                    "\t.balign 8\n"                     \
		    STAP_PROBE_ADDR(semaphore "\n")	\
  		    "\t.balign 8\n"			\
		    "3:\n\t.asciz " arg_format "\n"	\
		    "\t.balign 8\n"			\
		    "2:\n\t.asciz " #provider "\n"	\
		    "\t.balign 8\n"			\
		    "1:\n\t.asciz " #probe "\n"		\
		    "\t.previous\n" :: __stap_ ## args)
#endif
#if defined STAP_HAS_SEMAPHORES
 #if defined STAP_SDT_V1
  #define STAP_PROBE_DATA(provider,probe,guard,argc,arg_format,args) \
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,#arg_format,args,#probe "_semaphore")
#elif defined STAP_SDT_V2 || ! defined STAP_SDT_V1
  #define STAP_PROBE_DATA(provider,probe,guard,argc,arg_format,args) \
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,#arg_format,args,#provider "_" #probe "_semaphore")
 #endif
#else
 #define STAP_PROBE_DATA(provider,probe,guard,argc,arg_format,args) \
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,#arg_format,args,"")
#endif

/* Taking the address of a local label and/or referencing alloca prevents the
   containing function from being inlined, which keeps the parameters visible. */

#if __GNUC__ == 4 && __GNUC_MINOR__ <= 1
 #include <alloca.h>
 #define STAP_UNINLINE alloca((size_t)0)
#else
 #define STAP_UNINLINE
#endif


#if defined __x86_64__ || defined __i386__  || defined __powerpc__ || defined __arm__ || defined __sparc__
 #define STAP_NOP "\tnop "
#else
 #define STAP_NOP "\tnop 0 "
#endif

#ifndef STAP_SDT_VOLATILE /* allow users to override */
 #if (__GNUC__ >= 4 && __GNUC_MINOR__ >= 5 \
     || (defined __GNUC_RH_RELEASE__ \
         && __GNUC__ == 4 && __GNUC_MINOR__ == 4 && __GNUC_PATCHLEVEL__ >= 3 \
         && (__GNUC_PATCHLEVEL__ > 3 || __GNUC_RH_RELEASE__ >= 10)))
  #define STAP_SDT_VOLATILE
 #else
  #define STAP_SDT_VOLATILE volatile
 #endif
#endif


/* https://bugzilla.redhat.com/show_bug.cgi?id=608768 /
   http://gcc.gnu.org/PR44707 indicate that "g" is a good general
   register constraint for these operands, except on AUTO_INC_DEC
   targets.  Let's prefer "g" on fixed compilers and on other
   architectures.  The #if monstrosity was coded by Jakub Jalinek. */
#if defined (__i386__) || defined (__x86_64__) \
  || defined (__sparc__) || defined (__s390__) \
  || (__GNUC__ > 4)                            \
  || (__GNUC__ == 4                            \
  && (__GNUC_MINOR__ >= 6                       \
      || (defined __GNUC_RH_RELEASE__           \
          && (__GNUC_MINOR__ > 4                \
              || (__GNUC_MINOR__ == 4                   \
                  && (__GNUC_PATCHLEVEL__ > 4           \
                      || (__GNUC_PATCHLEVEL__ == 4              \
                          && __GNUC_RH_RELEASE__ >= 9)))))))
#define STAP_G_CONSTRAINT "g"
#else
#define STAP_G_CONSTRAINT "nro"
#endif
 

/* variadic macro args not allowed by -ansi -pedantic so... */
/* Use "ron" constraint as "g" constraint sometimes gives an auto increment operand */
#define __stap_arg0
#define __stap_arg1 STAP_G_CONSTRAINT(arg1)
#define __stap_arg2 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2)
#define __stap_arg3 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3)
#define __stap_arg4 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4)
#define __stap_arg5 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5)
#define __stap_arg6 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5), STAP_G_CONSTRAINT(arg6)
#define __stap_arg7 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5), STAP_G_CONSTRAINT(arg6), STAP_G_CONSTRAINT(arg7)
#define __stap_arg8 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5), STAP_G_CONSTRAINT(arg6), STAP_G_CONSTRAINT(arg7), STAP_G_CONSTRAINT(arg8)
#define __stap_arg9 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5), STAP_G_CONSTRAINT(arg6), STAP_G_CONSTRAINT(arg7), STAP_G_CONSTRAINT(arg8), STAP_G_CONSTRAINT(arg9)
#define __stap_arg10 STAP_G_CONSTRAINT(arg1), STAP_G_CONSTRAINT(arg2), STAP_G_CONSTRAINT(arg3), STAP_G_CONSTRAINT(arg4), STAP_G_CONSTRAINT(arg5), STAP_G_CONSTRAINT(arg6), STAP_G_CONSTRAINT(arg7), STAP_G_CONSTRAINT(arg8), STAP_G_CONSTRAINT(arg9), STAP_G_CONSTRAINT(arg10)

#if defined STAP_SDT_V1
 #define STAP_PROBE_POINT(provider,probe,argc,arg_format,args)	\
  STAP_UNINLINE;						\
  STAP_PROBE_DATA(provider,probe,STAP_UPROBE_GUARD,2f,nil,nil);	\
  __asm__ volatile ("2:\n" STAP_NOP "/* " arg_format " */" :: __stap_ ## args);
 #define STAP_PROBE(provider,probe)             			\
 do {								\
  STAP_PROBE_DATA(provider,probe,STAP_UPROBE_GUARD,2f,nil,nil);	\
  __asm__ volatile ("2:\n" STAP_NOP);				\
 } while (0)
#elif defined STAP_SDT_V2 || ! defined STAP_SDT_V1
 #define STAP_PROBE_POINT(provider,probe,argc,arg_format,args)   \
  STAP_UNINLINE;                                                \
  STAP_PROBE_DATA(provider,probe,STAP_UPROBE_GUARD,argc,arg_format,args);	\
  __asm__ volatile ("4:\n" STAP_NOP);
 #define STAP_PROBE(provider,probe)                      \
 do {							\
  STAP_PROBE_DATA(provider,probe,STAP_UPROBE_GUARD,0,"",arg0);	\
  __asm__ volatile ("4:\n" STAP_NOP);			\
 } while (0)
#endif

#define STAP_PROBE1(provider,probe,parm1)			\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);	\
  STAP_PROBE_POINT(provider,probe, 1, "%0", arg1)	\
  } while (0)

#define STAP_PROBE2(provider,probe,parm1,parm2)			\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);	\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);	\
  STAP_PROBE_POINT(provider,probe, 2, "%0 %1", arg2);	\
  } while (0)

#define STAP_PROBE3(provider,probe,parm1,parm2,parm3)		\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);	\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);	\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);	\
  STAP_PROBE_POINT(provider,probe, 3, "%0 %1 %2", arg3);	\
  } while (0)

#define STAP_PROBE4(provider,probe,parm1,parm2,parm3,parm4)		\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_PROBE_POINT(provider,probe, 4, "%0 %1 %2 %3", arg4);	\
  } while (0)

#define STAP_PROBE5(provider,probe,parm1,parm2,parm3,parm4,parm5)	\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = STAP_CAST(parm5);		\
  STAP_PROBE_POINT(provider,probe, 5, "%0 %1 %2 %3 %4", arg5);	\
  } while (0)

#define STAP_PROBE6(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6)	\
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = STAP_CAST(parm5);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm6) arg6 = STAP_CAST(parm6);		\
  STAP_PROBE_POINT(provider,probe, 6, "%0 %1 %2 %3 %4 %5", arg6); \
  } while (0)

#define STAP_PROBE7(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7) \
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = STAP_CAST(parm5);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm6) arg6 = STAP_CAST(parm6);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm7) arg7 = STAP_CAST(parm7);		\
  STAP_PROBE_POINT(provider,probe, 7, "%0 %1 %2 %3 %4 %5 %6", arg7);	\
  } while (0)

#define STAP_PROBE8(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8) \
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = STAP_CAST(parm5);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm6) arg6 = STAP_CAST(parm6);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm7) arg7 = STAP_CAST(parm7);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm8) arg8 = STAP_CAST(parm8);		\
  STAP_PROBE_POINT(provider,probe, 8, "%0 %1 %2 %3 %4 %5 %6 %7", arg8);	\
  } while (0)

#define STAP_PROBE9(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9) \
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = STAP_CAST(parm1);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = STAP_CAST(parm2);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = STAP_CAST(parm3);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = STAP_CAST(parm4);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = STAP_CAST(parm5);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm6) arg6 = STAP_CAST(parm6);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm7) arg7 = STAP_CAST(parm7);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm8) arg8 = STAP_CAST(parm8);		\
  STAP_SDT_VOLATILE STAP_TYPE(parm9) arg9 = STAP_CAST(parm9);		\
  STAP_PROBE_POINT(provider,probe, 9, "%0 %1 %2 %3 %4 %5 %6 %7 %8", arg9); \
  } while (0)

#define STAP_PROBE10(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9,parm10) \
  do { STAP_SDT_VOLATILE STAP_TYPE(parm1) arg1 = parm1;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm2) arg2 = parm2;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm3) arg3 = parm3;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm4) arg4 = parm4;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm5) arg5 = parm5;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm6) arg6 = parm6;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm7) arg7 = parm7;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm8) arg8 = parm8;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm9) arg9 = parm9;			\
  STAP_SDT_VOLATILE STAP_TYPE(parm10) arg10 = parm10;			\
  STAP_PROBE_POINT(provider,probe, 10, "%0 %1 %2 %3 %4 %5 %6 %7 %8 %9", arg10); \
  } while (0)

#else /* ! defined EXPERIMENTAL_KPROBE_SDT */
#include <unistd.h>
#include <sys/syscall.h>
#if defined (__USE_ANSI)
extern long int syscall (long int __sysno, ...) __THROW;
#endif

#include <sys/syscall.h>

/* An allocated section .probes that holds the probe names and addrs. */
#define STAP_SYSCALL __NR_getegid
#if defined STAP_SDT_V1
 #define STAP_GUARD KPROBE1_TYPE
 #define STAP_PROBE_DATA_(provider,probe,guard,arg,semaphore)	\
  __asm__ volatile (".section .probes," ALLOCSEC "\n"	\
		    "\t.balign 8\n"			\
		    "1:\n\t.asciz " #probe "\n"         \
		    "\t.balign 4\n"                     \
		    "\t.int " #guard "\n"		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR("1b\n")             \
		    "\t.balign 8\n"                     \
		    STAP_PROBE_ADDR(#arg "\n")		\
		    "\t.int 0\n"			\
		    "\t.previous\n")
#elif defined STAP_SDT_V2 || ! defined STAP_SDT_V1
 #define STAP_GUARD KPROBE2_TYPE
 #define STAP_PROBE_DATA_(provider,probe,guard,argc,semaphore)	\
  __asm__ volatile (".section .probes," ALLOCSEC "\n"	\
		    "\t.balign 8\n"			\
		    "\t.int " #guard "\n"		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR ("1f\n")		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR ("2f\n")		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR (#argc "\n")	\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR ("0\n")		\
		    "\t.balign 8\n"			\
		    STAP_PROBE_ADDR ("0\n")		\
                    "\t.balign 8\n"                     \
		    STAP_PROBE_ADDR(semaphore "\n")	\
		    "\t.balign 8\n"			\
		    "2:\t.asciz " #provider "\n"	\
		    "\t.balign 8\n"			\
		    "1:\n\t.asciz " #probe "\n"		\
		    "\t.int 0\n"			\
		    "\t.previous\n")
#endif

#if defined STAP_HAS_SEMAPHORES
 #if defined STAP_SDT_V1
  #define STAP_PROBE_DATA(provider,probe, guard, argc)	\
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,"")
 #elif defined STAP_SDT_V2 || ! defined STAP_SDT_V1
  #define STAP_PROBE_DATA(provider,probe, guard, argc)	\
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,#provider "_" #probe "_semaphore")
 #endif
#else
  #define STAP_PROBE_DATA(provider,probe, guard, argc)	\
  STAP_PROBE_DATA_(#provider,#probe,guard,argc,"")
#endif

#define STAP_PROBE(provider,probe)			\
  do { STAP_PROBE_DATA(provider,probe,STAP_GUARD,0);     \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD);	\
  } while (0)

#define STAP_PROBE1(provider,probe,parm1)				\
  do { STAP_PROBE_DATA(provider,probe,STAP_GUARD,1);                     \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, (size_t)parm1);		\
  } while (0)

#define STAP_PROBE2(provider,probe,parm1,parm2)				\
  do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));}			\
  stap_probe2_args = {(size_t)parm1, (size_t)parm2};			\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,2);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe2_args);	\
  } while (0)

#define STAP_PROBE3(provider,probe,parm1,parm2,parm3)			\
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));}			\
  stap_probe3_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3};	\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,3);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe3_args);	\
  } while (0)

#define STAP_PROBE4(provider,probe,parm1,parm2,parm3,parm4)		\
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));}			\
  stap_probe4_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4}; \
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,4);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD,&stap_probe4_args);		\
  } while (0)

#define STAP_PROBE5(provider,probe,parm1,parm2,parm3,parm4,parm5)	\
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));}			\
  stap_probe5_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5};							\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,5);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe5_args);	\
  } while (0)

#define STAP_PROBE6(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6)	\
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));			\
	  size_t arg6 __attribute__((aligned(8)));}			\
  stap_probe6_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5, (size_t)parm6};					\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,6);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe6_args);	\
  } while (0)

#define STAP_PROBE7(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7) \
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));			\
	  size_t arg6 __attribute__((aligned(8)));			\
	  size_t arg7 __attribute__((aligned(8)));}			\
  stap_probe7_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5, (size_t)parm6, (size_t)parm7};			\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,7);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe7_args);	\
  } while (0)

#define STAP_PROBE8(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8) \
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));			\
	  size_t arg6 __attribute__((aligned(8)));			\
	  size_t arg7 __attribute__((aligned(8)));			\
	  size_t arg8 __attribute__((aligned(8)));}			\
  stap_probe8_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5, (size_t)parm6, (size_t)parm7, (size_t)parm8};	\
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,8);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe8_args);	\
  } while (0)

#define STAP_PROBE9(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9) \
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));			\
	  size_t arg6 __attribute__((aligned(8)));			\
	  size_t arg7 __attribute__((aligned(8)));			\
	  size_t arg8 __attribute__((aligned(8)));			\
	  size_t arg9 __attribute__((aligned(8)));}			\
  stap_probe9_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5, (size_t)parm6, (size_t)parm7, (size_t)parm8, (size_t)parm9}; \
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,9);                         \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe9_args);	\
  } while (0)

#define STAP_PROBE10(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9,parm10) \
do { __extension__ struct {size_t arg1 __attribute__((aligned(8)));	\
	  size_t arg2 __attribute__((aligned(8)));			\
	  size_t arg3 __attribute__((aligned(8)));			\
	  size_t arg4 __attribute__((aligned(8)));			\
	  size_t arg5 __attribute__((aligned(8)));			\
	  size_t arg6 __attribute__((aligned(8)));			\
	  size_t arg7 __attribute__((aligned(8)));			\
	  size_t arg8 __attribute__((aligned(8)));			\
	  size_t arg9 __attribute__((aligned(8)));			\
	  size_t arg10 __attribute__((aligned(8)));}			\
  stap_probe10_args = {(size_t)parm1, (size_t)parm2, (size_t)parm3, (size_t)parm4, \
	(size_t)parm5, (size_t)parm6, (size_t)parm7, (size_t)parm8, (size_t)parm9, (size_t)parm10}; \
  STAP_PROBE_DATA(provider,probe,STAP_GUARD,10);                        \
  syscall (STAP_SYSCALL, #probe, STAP_GUARD, &stap_probe10_args);	\
  } while (0)

#endif

#define DTRACE_PROBE(provider,probe) \
STAP_PROBE(provider,probe)
#define DTRACE_PROBE1(provider,probe,parm1) \
STAP_PROBE1(provider,probe,parm1)
#define DTRACE_PROBE2(provider,probe,parm1,parm2) \
STAP_PROBE2(provider,probe,parm1,parm2)
#define DTRACE_PROBE3(provider,probe,parm1,parm2,parm3) \
STAP_PROBE3(provider,probe,parm1,parm2,parm3)
#define DTRACE_PROBE4(provider,probe,parm1,parm2,parm3,parm4) \
STAP_PROBE4(provider,probe,parm1,parm2,parm3,parm4)
#define DTRACE_PROBE5(provider,probe,parm1,parm2,parm3,parm4,parm5) \
STAP_PROBE5(provider,probe,parm1,parm2,parm3,parm4,parm5)
#define DTRACE_PROBE6(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6) \
STAP_PROBE6(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6)
#define DTRACE_PROBE7(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7) \
STAP_PROBE7(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7)
#define DTRACE_PROBE8(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8) \
STAP_PROBE8(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8)
#define DTRACE_PROBE9(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9) \
STAP_PROBE9(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9)
#define DTRACE_PROBE10(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9,parm10) \
  STAP_PROBE10(provider,probe,parm1,parm2,parm3,parm4,parm5,parm6,parm7,parm8,parm9,parm10)

#endif /* sys/sdt.h */
