#ifndef __SPFS_PTRACE_H__
#define __SPFS_PTRACE_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>
#include "include/list.h"

typedef _Bool bool;
typedef uint32_t u32;
enum {
	false	= 0,
	true	= 1
};

#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

#define min(x, y) ({	\
	typeof(x) _min1 = (x);		\
	typeof(y) _min2 = (y);		\
	(void) (&_min1 == &_min2);	\
	_min1 < _min2 ? _min1 : _min2; })

#define BUILTIN_SYSCALL_SIZE	8

#ifndef  __NR_memfd_create
#define __NR_memfd_create 319
#endif

#ifndef PTRACE_GETSIGMASK
# define PTRACE_GETSIGMASK      0x420a
# define PTRACE_SETSIGMASK      0x420b
#endif

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP       128
#endif

#define ARCH_SI_TRAP SI_KERNEL
#define SI_EVENT(_si_code)	(((_si_code) & 0xFFFF) >> 8)

#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */
#define X86_EFLAGS_IF	0x00000200 /* Interrupt Flag */
#define X86_EFLAGS_DF	0x00000400 /* Direction Flag */
#define TASK_SIZE	((1UL << 47) - PAGE_SIZE)

#define _KNSIG		64
# define _NSIG_BPW	64
#define _KNSIG_WORDS	(_KNSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_KNSIG_WORDS];
} k_rtsigset_t;

typedef struct {
	unsigned long   r15;
	unsigned long   r14;
	unsigned long   r13;
	unsigned long   r12;
	unsigned long   bp;
	unsigned long   bx;
	unsigned long   r11;
	unsigned long   r10;
	unsigned long   r9;
	unsigned long   r8;
	unsigned long   ax;
	unsigned long   cx;
	unsigned long   dx;
	unsigned long   si;
	unsigned long   di;
	unsigned long   orig_ax;
	unsigned long   ip;
	unsigned long   cs;
	unsigned long   flags;
	unsigned long   sp;
	unsigned long   ss;
	unsigned long   fs_base;
	unsigned long   gs_base;
	unsigned long   ds;
	unsigned long   es;
	unsigned long   fs;
	unsigned long   gs;
} user_regs_struct_t;

struct thread_ctx {
	k_rtsigset_t		sigmask;
	user_regs_struct_t	regs;
};

struct parasite_ctl {
	void			*remote_map;
	void			*local_map;

	struct sockaddr_un	remote_addr;
	socklen_t		remote_addrlen;
	struct sockaddr_un	local_addr;
	socklen_t		local_addrlen;

	int			remote_sockfd;
	int			local_sockfd;

	unsigned		map_length;
	pid_t			pid;
	unsigned long		syscall_ip;
	unsigned long		syscall_ip_saved;
	struct thread_ctx	orig;
	struct list_head	maps;
};

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes);
int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes);
int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes);

int get_thread_ctx(int pid, struct thread_ctx *ctx);

int syscall_seized(struct parasite_ctl *ctl, int nr, unsigned long *ret,
		   unsigned long arg1,
		   unsigned long arg2,
		   unsigned long arg3,
		   unsigned long arg4,
		   unsigned long arg5,
		   unsigned long arg6);

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset);

ssize_t sendmsg_seized(struct parasite_ctl *ctl, int sockfd,
		       const struct msghdr *msg, int flags);
ssize_t recvmsg_seized(struct parasite_ctl *ctl, int sockfd,
		       struct msghdr *msg, int flags);

int close_seized(struct parasite_ctl *ctl, int fd);
#endif
