#ifndef __SPFS_MANAGER_PID_UTIL_FD_H__
#define __SPFS_MANAGER_PID_UTIL_FD_H__

struct fd_opts {
	char flags;
	struct {
		u32 uid;
		u32 euid;
		u32 signum;
		u32 pid_type;
		u32 pid;
	} fown;
};

extern int send_fds(int sock, struct sockaddr_un *saddr, int saddr_len,
		    int *fds, int nr_fds, bool with_flags);
extern int recv_fds(struct parasite_ctl *ctl, int *fds, int nr_fds, struct fd_opts *opts);

static inline int send_fd(int sock, struct sockaddr_un *saddr, int saddr_len, int fd)
{
	return send_fds(sock, saddr, saddr_len, &fd, 1, false);
}

static inline int recv_fd(struct parasite_ctl *ctl)
{
	int fd, ret;

	ret = recv_fds(ctl, &fd, 1, NULL);
	if (ret)
		return -1;
	return fd;
}

#endif
