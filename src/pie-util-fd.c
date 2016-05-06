#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syscall.h>

#include "include/ptrace.h"
#include "include/pie-util-fd.h"
#include "include/log.h"

#define CR_SCM_MSG_SIZE		(1024)
#define CR_SCM_MAX_FD		(252)

struct scm_fdset {
	struct msghdr	hdr;
	struct iovec	iov;
	char		msg_buf[CR_SCM_MSG_SIZE];
	struct fd_opts	opts[CR_SCM_MAX_FD];
};

#ifndef F_SETOWN_EX
#define F_SETOWN_EX     15
#define F_GETOWN_EX     16
struct f_owner_ex {
	int	type;
	pid_t	pid;
};
#endif

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS 17
#endif

static void scm_fdset_init_chunk(struct scm_fdset *fdset, int nr_fds)
{
	struct cmsghdr *cmsg;

	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * nr_fds);

	cmsg		= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len	= fdset->hdr.msg_controllen;
}

static int *scm_fdset_init(struct scm_fdset *fdset, struct sockaddr_un *saddr,
		int saddr_len, bool with_flags)
{
	struct cmsghdr *cmsg;

	fdset->iov.iov_base		= fdset->opts;
	fdset->iov.iov_len		= with_flags ? sizeof(fdset->opts) : 1;

	fdset->hdr.msg_iov		= &fdset->iov;
	fdset->hdr.msg_iovlen		= 1;
	fdset->hdr.msg_name		= (struct sockaddr *)saddr;
	fdset->hdr.msg_namelen		= saddr_len;

	fdset->hdr.msg_control		= &fdset->msg_buf;
	fdset->hdr.msg_controllen	= CMSG_LEN(sizeof(int) * CR_SCM_MAX_FD);

	cmsg				= CMSG_FIRSTHDR(&fdset->hdr);
	cmsg->cmsg_len			= fdset->hdr.msg_controllen;
	cmsg->cmsg_level		= SOL_SOCKET;
	cmsg->cmsg_type			= SCM_RIGHTS;

	return (int *)CMSG_DATA(cmsg);
}

int send_fds(int sock, struct sockaddr_un *saddr, int len,
		int *fds, int nr_fds, bool with_flags)
{
	struct scm_fdset fdset;
	int *cmsg_data;
	int i, min_fd, ret;

	cmsg_data = scm_fdset_init(&fdset, saddr, len, with_flags);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(&fdset, min_fd);
		memcpy(cmsg_data, &fds[i], sizeof(int) * min_fd);

		if (with_flags) {
			int j;

			for (j = 0; j < min_fd; j++) {
				int flags, fd = fds[i + j];
				struct fd_opts *p = fdset.opts + j;
				struct f_owner_ex owner_ex;
				u32 v[2];

				flags = fcntl(fd, F_GETFD, 0);
				if (flags < 0) {
					pr_perror("fcntl(%d, F_GETFD) -> %d", fd, flags);
					return -1;
				}

				p->flags = (char)flags;

				ret = fcntl(fd, F_GETOWN_EX, (long)&owner_ex);
				if (ret) {
					pr_perror("fcntl(%d, F_GETOWN_EX) -> %d", fd, ret);
					return -1;
				}

				/*
				 * Simple case -- nothing is changed.
				 */
				if (owner_ex.pid == 0) {
					p->fown.pid = 0;
					continue;
				}

				ret = fcntl(fd, F_GETOWNER_UIDS, (long)&v);
				if (ret) {
					pr_perror("fcntl(%d, F_GETOWNER_UIDS) -> %d", fd, ret);
					return -1;
				}

				p->fown.uid	 = v[0];
				p->fown.euid	 = v[1];
				p->fown.pid_type = owner_ex.type;
				p->fown.pid	 = owner_ex.pid;
			}
		}

		ret = sendmsg(sock, &fdset.hdr, 0);
		if (ret <= 0)
			return ret ? : -1;
	}

	return 0;
}

int recv_fds(struct parasite_ctl *ctl, int *fds, int nr_fds, struct fd_opts *opts)
{
	struct scm_fdset *fdset = (void *)ctl->local_map;
	struct cmsghdr *cmsg;
	unsigned long sret;
	int *cmsg_data;
	int ret;
	int i, min_fd;

	cmsg_data = scm_fdset_init(fdset, NULL, 0, opts != NULL);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(fdset, min_fd);

		ret = syscall_seized(ctl, __NR_recvmsg, &sret,
				     ctl->remote_sockfd, (unsigned long)&fdset->hdr,
				     0, 0, 0, 0);
		if (ret < 0 || (int)(long)sret < 0) {
			pr_err("Can't receive sock\n");
			return -1;
		}

		cmsg = CMSG_FIRSTHDR(&fdset->hdr);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS)
			return -EINVAL;
		if (fdset->hdr.msg_flags & MSG_CTRUNC)
			return -ENFILE;

		min_fd = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
		/*
		 * In case if kernel screwed the recepient, most probably
		 * the caller stack frame will be overwriten, just scream
		 * and exit.
		 *
		 * FIXME Need to sanitize util.h to be able to include it
		 * into files which do not have glibc and a couple of
		 * sys_write_ helpers. Meawhile opencoded BUG_ON here.
		 */
		if (min_fd > CR_SCM_MAX_FD) {
			pr_err("Too big min_fd\n");
			return -1;
		}

		if (min_fd <= 0)
			return -1;
		memcpy(&fds[i], cmsg_data, sizeof(int) * min_fd);
		if (opts)
			memcpy(opts + i, fdset->opts, sizeof(struct fd_opts) * min_fd);
	}

	return 0;
}
