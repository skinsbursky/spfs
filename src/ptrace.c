#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <syscall.h>
#include <string.h>
#include <signal.h>
#include <alloca.h>
#include <errno.h>
#include <stdio.h>
#include <elf.h>

#include "include/ptrace.h"
#include "include/log.h"

/*
 * Injected syscall instruction
 */
const char code_syscall[] = {
	0x0f, 0x05,				/* syscall    */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
};

const char code_int_80[] = {
	0xcd, 0x80,				/* int $0x80  */
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc	/* int 3, ... */
};

int ptrace_peek_area(pid_t pid, void *dst, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *d = dst, *a = addr;
		errno = 0;
		d[w] = ptrace(PTRACE_PEEKDATA, pid, a + w, NULL);
		if (d[w] == -1U && errno)
			goto err;
	}
	return 0;
err:
	return -2;
}

int ptrace_poke_area(pid_t pid, void *src, void *addr, long bytes)
{
	unsigned long w;
	if (bytes & (sizeof(long) - 1))
		return -1;
	for (w = 0; w < bytes / sizeof(long); w++) {
		unsigned long *s = src, *a = addr;
		if (ptrace(PTRACE_POKEDATA, pid, a + w, s[w]))
			goto err;
	}
	return 0;
err:
	return -2;
}

/* don't swap big space, it might overflow the stack */
int ptrace_swap_area(pid_t pid, void *dst, void *src, long bytes)
{
	void *t = alloca(bytes);

	if (ptrace_peek_area(pid, t, dst, bytes))
		return -1;

	if (ptrace_poke_area(pid, src, dst, bytes)) {
		if (ptrace_poke_area(pid, t, dst, bytes))
			return -2;
		return -1;
	}

	memcpy(src, t, bytes);

	return 0;
}

static int ptrace_get_regs(pid_t pid, user_regs_struct_t *regs)
{
	struct iovec iov;
	int ret;

	iov.iov_base = &regs->native;
	iov.iov_len = sizeof(user_regs_struct64);

	ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	if (iov.iov_len == sizeof(regs->native)) {
		regs->__is_native = NATIVE_MAGIC;
		return ret;
	}
	if (iov.iov_len == sizeof(regs->compat)) {
		regs->__is_native = COMPAT_MAGIC;
		return ret;
	}

	pr_err("PTRACE_GETREGSET read %zu bytes for pid %d, but native/compat regs sizes are %zu/%zu bytes",
			iov.iov_len, pid,
			sizeof(regs->native), sizeof(regs->compat));
	return -1;
}

static int ptrace_set_regs(pid_t pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	if (user_regs_native(regs)) {
		iov.iov_base = &regs->native;
		iov.iov_len = sizeof(user_regs_struct64);
	} else {
		iov.iov_base = &regs->compat;
		iov.iov_len = sizeof(user_regs_struct32);
	}
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

int get_thread_ctx(int pid, struct thread_ctx *ctx)
{
	if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("can't get signal blocking mask for %d", pid);
		return -1;
	}

	if (ptrace_get_regs(pid, &ctx->regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
		return -1;
	}

	return 0;
}

static int restore_thread_ctx(int pid, struct thread_ctx *ctx)
{
	int ret = 0;

	if (ptrace_set_regs(pid, &ctx->regs)) {
		pr_perror("Can't restore registers (pid: %d)", pid);
		ret = -1;
	}
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &ctx->sigmask)) {
		pr_perror("Can't block signals");
		ret = -1;
	}

	return ret;
}

static inline void ksigfillset(k_rtsigset_t *set)
{
	int i;
	for (i = 0; i < _KNSIG_WORDS; i++)
	set->sig[i] = (unsigned long)-1;
}

void parasite_setup_regs(unsigned long new_ip, void *stack, user_regs_struct_t *regs)
{
	set_user_reg(regs, ip, new_ip);
	if (stack)
		set_user_reg(regs, sp, (unsigned long) stack);

	/* Avoid end of syscall processing */
	set_user_reg(regs, orig_ax, -1);

	/* Make sure flags are in known state */
	set_user_reg(regs, flags, get_user_reg(regs, flags) &
		     ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF));
}

static int parasite_run(pid_t pid, int cmd, unsigned long ip, void *stack,
		user_regs_struct_t *regs, struct thread_ctx *octx)
{
	k_rtsigset_t block;

	ksigfillset(&block);
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &block)) {
		pr_perror("Can't block signals for %d", pid);
		goto err_sig;
	}

	parasite_setup_regs(ip, stack, regs);
	if (ptrace_set_regs(pid, regs)) {
		pr_perror("Can't set registers for %d", pid);
		goto err_regs;
	}

	if (ptrace(cmd, pid, NULL, NULL)) {
		pr_perror("Can't run parasite at %d", pid);
		goto err_cont;
	}

	return 0;

err_cont:
	if (ptrace_set_regs(pid, &octx->regs))
		pr_perror("Can't restore regs for %d", pid);
err_regs:
	if (ptrace(PTRACE_SETSIGMASK, pid, sizeof(k_rtsigset_t), &octx->sigmask))
		pr_perror("Can't restore sigmask for %d", pid);
err_sig:
	return -1;
}

/* we run at @regs->ip */
static int parasite_trap(struct parasite_ctl *ctl, pid_t pid,
				user_regs_struct_t *regs,
				struct thread_ctx *octx)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_perror("Waited pid mismatch (pid: %d)", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_err("Can't get siginfo (pid: %d)", pid);
		goto err;
	}

	if (ptrace_get_regs(pid, regs)) {
		pr_perror("Can't obtain registers (pid: %d)", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != ARCH_SI_TRAP) {
		pr_err("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		pr_err("Unexpected %d task interruption, aborting\n", pid);
		goto err;
	}

	/*
	 * We've reached this point if int3 is triggered inside our
	 * parasite code. So we're done.
	 */
	ret = 0;
err:
	if (restore_thread_ctx(pid, octx))
		ret = -1;

	return ret;
}

static int __parasite_execute_syscall(struct parasite_ctl *ctl,
				      user_regs_struct_t *regs, const char *code_syscall)
{
	pid_t pid = ctl->pid;
	int err;
	uint8_t code_orig[BUILTIN_SYSCALL_SIZE];

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	memcpy(code_orig, code_syscall, sizeof(code_orig));
	if (ptrace_swap_area(pid, (void *)ctl->syscall_ip,
			     (void *)code_orig, sizeof(code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		return -1;
	}

	err = parasite_run(pid, PTRACE_CONT, ctl->syscall_ip, 0, regs, &ctl->orig);
	if (!err)
		err = parasite_trap(ctl, pid, regs, &ctl->orig);

	if (ptrace_poke_area(pid, (void *)code_orig,
			     (void *)ctl->syscall_ip, sizeof(code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid);
		err = -1;
	}

	return err;
}

int syscall_seized(struct parasite_ctl *ctl, int nr, unsigned long *ret,
		unsigned long arg1,
		unsigned long arg2,
		unsigned long arg3,
		unsigned long arg4,
		unsigned long arg5,
		unsigned long arg6)
{
	user_regs_struct_t regs = ctl->orig.regs;
	int err;

	if (user_regs_native(&regs)) {
		user_regs_struct64 *r = &regs.native;

		r->ax  = (uint64_t)nr;
		r->di  = arg1;
		r->si  = arg2;
		r->dx  = arg3;
		r->r10 = arg4;
		r->r8  = arg5;
		r->r9  = arg6;

		err = __parasite_execute_syscall(ctl, &regs, code_syscall);
	} else {
		user_regs_struct32 *r = &regs.compat;

		r->ax  = (uint32_t)nr;
		r->bx  = arg1;
		r->cx  = arg2;
		r->dx  = arg3;
		r->si  = arg4;
		r->di  = arg5;
		r->bp  = arg6;

		err = __parasite_execute_syscall(ctl, &regs, code_int_80);
	}

	*ret = get_user_reg(&regs, ax);
	return err;
}

void *mmap_seized(struct parasite_ctl *ctl,
		  void *addr, size_t length, int prot,
		  int flags, int fd, off_t offset)
{
	unsigned long map;
	int err;

	err = syscall_seized(ctl, __NR_mmap, &map,
			(unsigned long)addr, length, prot, flags, fd, offset);
	if (err < 0) {
		pr_err("Seized mmap call failed: %d\n", err);
		return NULL;
	}

	if (IS_ERR_VALUE(map)) {
		if (map == -EACCES && (prot & PROT_WRITE) && (prot & PROT_EXEC))
			pr_err("mmap(PROT_WRITE | PROT_EXEC) failed for %d, "
			       "check selinux execmem policy\n", ctl->pid);
		return NULL;
	}

	return (void *)map;
}

ssize_t sendmsg_seized(struct parasite_ctl *ctl, int sockfd, const struct msghdr *msg, int flags)
{
	unsigned long sret;
	int ret;

	ret = syscall_seized(ctl, __NR_sendmsg, &sret, sockfd,
			     (unsigned long)msg, flags, 0, 0, 0);
	if (ret < 0 || (int)(long)sret < 0) {
		pr_err("sendmsg_seized: %d %d\n", ret, (int)(long)sret);
		return -1;
	}

	return (ssize_t)sret;	
}

ssize_t recvmsg_seized(struct parasite_ctl *ctl, int sockfd, struct msghdr *msg, int flags)
{
	unsigned long sret;
	int ret;

	ret = syscall_seized(ctl, __NR_recvmsg, &sret, sockfd,
			     (unsigned long)msg, flags, 0, 0, 0);
	if (ret < 0 || (int)(long)sret < 0) {
		pr_err("recvmsg_seized: %d %d\n", ret, (int)(long)sret);
		return -1;
	}

	return (ssize_t)sret;	
}

int close_seized(struct parasite_ctl *ctl, int fd)
{
	unsigned long sret;
	int err;

	err = syscall_seized(ctl, __NR_close, &sret, fd, 0, 0, 0, 0, 0);
	if (err || sret) {
		pr_err("close: %d %d\n", err, (int)(long)sret);
		return -1;
	}
	return 0;
}

int fchdir_seized(struct parasite_ctl *ctl, int fd)
{
	unsigned long sret;
	int err;

	err = syscall_seized(ctl, __NR_fchdir, &sret, fd, 0, 0, 0, 0, 0);
	if (err || sret) {
		pr_err("fchdir: %d %d\n", err, (int)(long)sret);
		return -1;
	}
	return 0;
}
