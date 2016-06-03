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

/* Borrowed from kernel */
#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
		                                  (struct cmsghdr *)(ctl) : \
		                                  (struct cmsghdr *)NULL)

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

static void scm_fdset_init_chunk(struct scm_fdset *fdset, struct scm_fdset *rfdset, int nr_fds)
{
	struct cmsghdr *cmsg;

	fdset->hdr.msg_controllen = CMSG_LEN(sizeof(int) * nr_fds);

	cmsg		= __CMSG_FIRSTHDR(&fdset->msg_buf, fdset->hdr.msg_controllen);
	cmsg->cmsg_len	= fdset->hdr.msg_controllen;
}

static int *scm_fdset_init(struct scm_fdset *fdset, struct scm_fdset *rfdset,
			   struct sockaddr_un *saddr, int saddr_len, bool with_flags)
{
	struct cmsghdr *cmsg;

	fdset->iov.iov_base		= rfdset->opts;
	fdset->iov.iov_len		= with_flags ? sizeof(rfdset->opts) : 1;

	fdset->hdr.msg_iov		= &rfdset->iov;
	fdset->hdr.msg_iovlen		= 1;
	fdset->hdr.msg_name		= (struct sockaddr *)saddr;
	fdset->hdr.msg_namelen		= saddr_len;

	fdset->hdr.msg_control		= &rfdset->msg_buf;
	fdset->hdr.msg_controllen	= CMSG_LEN(sizeof(int) * CR_SCM_MAX_FD);

	cmsg				= __CMSG_FIRSTHDR(&fdset->msg_buf, fdset->hdr.msg_controllen);
	cmsg->cmsg_len			= fdset->hdr.msg_controllen;
	cmsg->cmsg_level		= SOL_SOCKET;
	cmsg->cmsg_type			= SCM_RIGHTS;

	return (int *)CMSG_DATA(cmsg);
}

int send_fds(struct parasite_ctl *ctl, bool seized, int *fds, int nr_fds, bool with_flags)
{
	struct scm_fdset *fdset, *rfdset;
	int i, min_fd, ret, sock;
	struct sockaddr_un *addr;
	socklen_t addrlen;
	int *cmsg_data;

	fdset = ctl->local_map;
	if (seized) {
		rfdset = ctl->remote_map;
		sock = ctl->remote_sockfd;
		addrlen = ctl->local_addrlen;
		addr = ctl->local_map + sizeof(*fdset);
		memcpy(addr, &ctl->local_addr, addrlen);
		addr = ctl->remote_map + sizeof(*fdset);
	} else {
		rfdset = fdset;
		sock = ctl->local_sockfd;
		addrlen = ctl->remote_addrlen;
		addr = &ctl->remote_addr;
	}

	cmsg_data = scm_fdset_init(fdset, rfdset, addr, addrlen, with_flags);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(fdset, rfdset, min_fd);
		memcpy(cmsg_data, &fds[i], sizeof(int) * min_fd);

		if (with_flags) {
			int j;

			for (j = 0; j < min_fd; j++) {
				int flags, fd = fds[i + j];
				struct fd_opts *p = fdset->opts + j;
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

		if (seized)
			ret = sendmsg_seized(ctl, sock, &rfdset->hdr, 0);
		else
			ret = sendmsg(sock, &fdset->hdr, 0);
		if (ret <= 0) {
			pr_err("sendmsg: %d%s\n", ret, seized ? "(seized)" : "\0");
			return ret ? : -1;
		}
	}

	return 0;
}

int recv_fds(struct parasite_ctl *ctl, bool seized, int *fds, int nr_fds, struct fd_opts *opts)
{
	struct scm_fdset *fdset, *rfdset;
	struct cmsghdr *cmsg;
	int *cmsg_data;
	int ret;
	int i, min_fd;

	fdset = ctl->local_map;
	if (seized)
		rfdset = ctl->remote_map;
	else
		rfdset = fdset;

	cmsg_data = scm_fdset_init(fdset, rfdset, NULL, 0, opts != NULL);
	for (i = 0; i < nr_fds; i += min_fd) {
		min_fd = min(CR_SCM_MAX_FD, nr_fds - i);
		scm_fdset_init_chunk(fdset, rfdset, min_fd);

		if (seized)
			ret = recvmsg_seized(ctl, ctl->remote_sockfd, &rfdset->hdr, 0);
		else
			ret = recvmsg(ctl->local_sockfd, &fdset->hdr, 0);

		if (ret < 0) {
			pr_err("recvmsg: %d%s\n", ret, seized ? "(seized)" : "\0");
			return -1;
		}

		cmsg = __CMSG_FIRSTHDR(&fdset->msg_buf, fdset->hdr.msg_controllen);
		if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
			pr_err("Crappy cmsg_type\n");
			return -EINVAL;
		}
		if (fdset->hdr.msg_flags & MSG_CTRUNC) {
			pr_err("Message truncated\n");
			return -ENFILE;
		}

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

		if (min_fd <= 0) {
			pr_err("Too small mid_fd=%d\n", min_fd);
			return -1;
		}
		memcpy(&fds[i], cmsg_data, sizeof(int) * min_fd);
		if (opts)
			memcpy(opts + i, fdset->opts, sizeof(struct fd_opts) * min_fd);
	}

	return 0;
}
