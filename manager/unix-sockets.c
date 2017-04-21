#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <linux/un.h>
#include <fcntl.h>

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <libnl3/netlink/msg.h>

#include "include/netlink.h"
#include "include/log.h"
#include "include/util.h"

#include "processes.h"
#include "trees.h"

struct unix_sk_diag_req {
	struct nlmsghdr		hdr;
	struct unix_diag_req	u;
};

struct unix_socket_info {
	unsigned int	ino;
	unsigned char	type;
	unsigned char	state;
	char		*path;
	ino_t		vfs_ino;
	dev_t		vfs_dev;
	ino_t		peer_ino;
	unsigned	rq_len;
	unsigned	wq_len;
	unsigned char	shutdown;
	unsigned int	*icons;
	unsigned int	nr_icons;
	int		fd;
	struct unix_socket_info	*peer;
};

#define KDEV_MINORBITS	20
#define KDEV_MINORMASK	((1UL << KDEV_MINORBITS) - 1)

typedef unsigned int u32;

static inline u32 kdev_major(u32 kdev)
{
	return kdev >> KDEV_MINORBITS;
}

static inline u32 kdev_minor(u32 kdev)
{
	return kdev & KDEV_MINORMASK;
}

static inline dev_t kdev_to_odev(u32 kdev)
{
	/*
	 * New kernels envcode devices in a new form
	 */
	return (kdev_major(kdev) << 8) | kdev_minor(kdev);
}

static int unix_process_name(struct nlattr **tb, char **path)
{
	int len;
	char name[PATH_MAX];

	len = nla_len(tb[UNIX_DIAG_NAME]);

	memcpy(name, nla_data(tb[UNIX_DIAG_NAME]), len);
	name[len] = '\0';

	*path = strdup(name);
	if (!*path)
		return -ENOMEM;
	return 0;
}

static int unix_socket_collect(struct unix_socket_info *sk)
{
	char *state, *type;
	char *info;

	switch (sk->state) {
		case TCP_LISTEN:
			state = "TCP_LISTEN";
			break;
		case TCP_ESTABLISHED:
			state = "TCP_ESTABLISHED";
			break;
		case TCP_CLOSE:
			state = "TCP_CLOSE";
			break;
		default:
			pr_err("unknown unix socket state: %d\n", sk->state);
			return -EINVAL;
	}

	switch (sk->type) {
		case SOCK_STREAM:
			type = "STREAM";
			break;
		case SOCK_DGRAM:
			type = "DGRAM";
			break;
		case SOCK_SEQPACKET:
			type = "SEQPACKET";
			break;
		default:
			pr_err("unknown unix socket type: %d\n", sk->type);
			return -EINVAL;
	}

	info = xsprintf("%d: type: %7s, state: %15s, peer: %10d, rq_len: %4d, wq_len: %4d",
			sk->ino, type, state, sk->peer_ino, sk->rq_len, sk->wq_len);
	if (info && sk->path)
		info = xstrcat(info, ", bind: %s", sk->path);
	if (!info)
		return -ENOMEM;
	pr_info("    %s\n", info);
	free(info);

	return collect_unix_socket(sk->ino, sk);
}

static struct unix_socket_info *alloc_unix_sk(void)
{
	struct unix_socket_info *sk;

	sk = malloc(sizeof(*sk));
	if (!sk) {
		pr_err("failed to allocated\n");
		return NULL;
	}
	memset(sk, 0, sizeof(*sk));
	sk->fd = -1;

	return sk;
}

static int unix_collect_connecting(unsigned int ino, unsigned type, struct unix_socket_info *lsk)
{
	struct unix_socket_info *sk;

	sk = alloc_unix_sk();
	if (!sk)
		return -ENOMEM;

	sk->ino = ino;
	sk->type  = type;
	sk->state = TCP_ESTABLISHED;
	sk->peer_ino = lsk->ino;
	sk->peer = lsk;

	return unix_socket_collect(sk);
}

static void unix_destroy_one(struct unix_socket_info *sk)
{
	/*TODO: "icons" sockets have to be released as well */
	free(sk->icons);
	free(sk->path);
	free(sk);
}

static int unix_create_one(const struct unix_diag_msg *m, struct nlattr **tb,
			   struct unix_socket_info **sock)
{
	struct unix_socket_info *sk;
	int err;

	sk = alloc_unix_sk();
	if (!sk)
		return -ENOMEM;

	sk->ino = m->udiag_ino;
	sk->type  = m->udiag_type;
	sk->state = m->udiag_state;

	if (tb[UNIX_DIAG_VFS]) {
		struct unix_diag_vfs *uv;

		uv = RTA_DATA(tb[UNIX_DIAG_VFS]);

		sk->vfs_dev = uv->udiag_vfs_ino;
		sk->vfs_ino = uv->udiag_vfs_dev;
	}

	if (tb[UNIX_DIAG_PEER])
		sk->peer_ino = nla_get_u32(tb[UNIX_DIAG_PEER]);

	if (tb[UNIX_DIAG_NAME]) {
		err = unix_process_name(tb, &sk->path);
		if (err)
			goto free_sk;
	}

	if (tb[UNIX_DIAG_RQLEN]) {
		struct unix_diag_rqlen *rq;

		rq = (struct unix_diag_rqlen *)RTA_DATA(tb[UNIX_DIAG_RQLEN]);
		sk->rq_len = rq->udiag_rqueue;
		sk->wq_len = rq->udiag_wqueue;
	}

	if (tb[UNIX_DIAG_SHUTDOWN])
		sk->shutdown = nla_get_u8(tb[UNIX_DIAG_SHUTDOWN]);


	if (tb[UNIX_DIAG_ICONS]) {
		int len = nla_len(tb[UNIX_DIAG_ICONS]);
		int i;
		unsigned int *icons = nla_data(tb[UNIX_DIAG_ICONS]);
		for (i = 0; i < len / sizeof(u32); i++) {
			err = unix_collect_connecting(icons[i], sk->type, sk);
			if (err)
				return err;
		}
		sk->nr_icons = len / sizeof(u32);
	}

	*sock = sk;
	return 0;

free_sk:
	free(sk);
	return err;
}

static int unix_collect_bound(const struct unix_diag_msg *m, struct nlattr **tb)
{
	struct unix_socket_info *sk;
	int err;

	err = unix_create_one(m, tb, &sk);
	if (err)
		return err;

	err = unix_socket_collect(sk);
	if (err)
		unix_destroy_one(sk);
	return 0;
}

static bool need_to_collect_bound(const struct unix_diag_msg *m,
				  struct nlattr **tb,
				  const struct replace_info_s *ri)
{
	struct unix_diag_vfs *uv;

	if (!tb[UNIX_DIAG_VFS]) {
		return false;
	}

	uv = RTA_DATA(tb[UNIX_DIAG_VFS]);
	if (uv->udiag_vfs_dev != ri->src_dev) {
		return false;
	}

	return true;
}

static LIST_HEAD(closed_sockets);

struct closed_socket {
	struct list_head	list;
	struct unix_socket_info	*sk;
};

static void unix_destroy_closed(struct closed_socket *cs)
{
	if (cs->sk)
		unix_destroy_one(cs->sk);
	free(cs);
}

static int unix_collect_closed(const struct unix_diag_msg *m, struct nlattr **tb)
{
	struct closed_socket *cs;
	struct unix_socket_info	*sk;
	int err;

	cs = malloc(sizeof(*cs));
	if (!cs) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	err = unix_create_one(m, tb, &sk);
	if (err) {
		free(cs);
		return err;
	}

	cs->sk = sk;
	list_add_tail(&cs->list, &closed_sockets);
	return 0;
}

static void unix_cleanup_closed_list(void)
{
	struct closed_socket *cs, *tmp;

	list_for_each_entry_safe(cs, tmp, &closed_sockets, list) {
		list_del(&cs->list);
		unix_destroy_closed(cs);
	}
}

static int process_closed_socket(struct unix_socket_info *sk)
{
	struct unix_socket_info *peer;

	if (find_unix_socket(sk->peer_ino, (void **)&peer))
		return 0;

	return unix_socket_collect(sk);
}

static int process_closed_sockets(void)
{
	struct closed_socket *cs;
	int err;

	/*TODO cleanup sockets list */
	list_for_each_entry(cs, &closed_sockets, list) {
		err = process_closed_socket(cs->sk);
		if (err)
			return err;
		cs->sk = NULL;
	}
	return 0;
}

static bool need_to_collect_closed(const struct unix_diag_msg *m,
				   struct nlattr **tb,
				   const struct replace_info_s *ri)
{
	if (m->udiag_state != TCP_CLOSE)
		return false;

	if (!tb[UNIX_DIAG_PEER])
		return false;

	if (!nla_get_u32(tb[UNIX_DIAG_PEER])) {
		pr_debug("unconnected socket with zero peer. Skip.\n");
		return false;
	}
	return true;
}

static int unix_receive_one(struct nlmsghdr *h, void *arg)
{
	struct unix_diag_msg *m = NLMSG_DATA(h);
	struct nlattr *tb[UNIX_DIAG_MAX+1];
	struct replace_info_s *ri = arg;

	nlmsg_parse(h, sizeof(struct unix_diag_msg), tb, UNIX_DIAG_MAX, NULL);

	if (need_to_collect_bound(m, tb, ri))
		return unix_collect_bound(m, tb);
	else if (need_to_collect_closed(m, tb, ri))
		return unix_collect_closed(m, tb);

	return 0;
}

static int do_collect_req(int nl, struct unix_sk_diag_req *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, void *), void *arg)
{
	return do_rtnl_req(nl, req, size, receive_callback, NULL, arg);
}

static int netlink_receive_sockets(struct replace_info_s *ri)
{
	int err;
	int nl;
	struct unix_sk_diag_req req;

	nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
	if (nl < 0) {
		pr_perror("failed to create netlink diag socket");
		return -errno;
	}

	memset(&req, 0, sizeof(req));
	req.hdr.nlmsg_len       = sizeof(req);
	req.hdr.nlmsg_type      = SOCK_DIAG_BY_FAMILY;
	req.hdr.nlmsg_flags     = NLM_F_DUMP | NLM_F_REQUEST;
	req.hdr.nlmsg_seq       = CR_NLMSG_SEQ;

	req.u.sdiag_family    = AF_UNIX;
	req.u.udiag_states    = (1 << TCP_CLOSE) | (1 << TCP_LISTEN);
	req.u.udiag_show      = UDIAG_SHOW_NAME | UDIAG_SHOW_VFS |
				UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS |
				UDIAG_SHOW_RQLEN;
	err = do_collect_req(nl, &req, sizeof(req), unix_receive_one, ri);

        close(nl);
	return err;
}

int collect_unix_sockets(struct replace_info_s *ri)
{
	int err;

	pr_debug("Collecting sockets:\n");

	err = netlink_receive_sockets(ri);
	if (!err)
		err = process_closed_sockets();
	unix_cleanup_closed_list();
	return 0;
}

static int sk_type_is_supported(unsigned char type)
{
	switch (type) {
		case SOCK_STREAM:
		case SOCK_DGRAM:
			return true;
		case SOCK_SEQPACKET:
			pr_err("Unix SOCK_SEQPACKET socket is not supported yet\n");
			break;
		default:
			pr_err("unknown unix socket type: %d\n", type);
			break;
	}
	return false;
}

static int sk_state_is_supported(unsigned char state)
{
	switch (state) {
		case TCP_ESTABLISHED:
		case TCP_LISTEN:
		case TCP_CLOSE:
			return true;
		default:
			pr_err("unknown unix socket state: %d\n", state);
			break;
	}
	return false;
}

static bool unix_sk_is_supported(const struct unix_socket_info *sk)
{
	if (!sk_type_is_supported(sk->type))
		return false;

	if (!sk_state_is_supported(sk->state))
		return false;
	return true;
}

static void unix_construct_addr(struct unix_socket_info *sk, struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, sk->path, sizeof(addr->sun_path) - 1);
}

static int unix_bind_socket(struct unix_socket_info *sk, int sock)
{
	struct sockaddr_un addr;
	struct stat st;

	/* Socket file can be deleted. It's not preserved on file systems like
	 * NFS.
	 */
	if (!access(sk->path, F_OK)) {
		if (stat(sk->path, &st)) {
			pr_perror("failed to stat %s", sk->path);
			return -errno;
		}

		if (unlink(sk->path)) {
			pr_perror("failed to unlink %s", sk->path);
			return -errno;
		}
	}

	unix_construct_addr(sk, &addr);

	if (bind(sock, (struct sockaddr *)&addr,
		   sizeof(addr.sun_family) + strlen(sk->path))) {
		pr_perror("failed to bind socket %d to path %s", sock, sk->path);
		return -errno;
	}

	if (chmod(sk->path, st.st_mode & ALLPERMS)) {
		pr_perror("failed to chmod %s to %#o", sk->path, st.st_mode & ALLPERMS);
		return -errno;
	}

	if (chown(sk->path, st.st_uid, st.st_gid)) {
		pr_perror("failed to chown %s to %d:%d", sk->path, st.st_uid, st.st_gid);
		return -errno;
	}

	return 0;
}

static int unix_listen_socket(struct unix_socket_info *sk, int sock)
{
	int err;

	err = unix_bind_socket(sk, sock);
	if (err < 0)
		return err;

	if (listen(sock, sk->wq_len)) {
		pr_err("failed to listen socket %d\n", sock);
		return -errno;
	}

	return 0;
}

static int unix_connect_socket(struct unix_socket_info *dest, int sock)
{
	struct sockaddr_un addr;

	unix_construct_addr(dest, &addr);

	if (connect(sock, (struct sockaddr *)&addr,
		   sizeof(addr.sun_family) + strlen(dest->path))) {
		pr_perror("failed to connect socket %d to path %s", sock, dest->path);
		return -errno;
	}
	return 0;
}

static int unix_unconn_socket(struct unix_socket_info *sk, int sock)
{
	int err;
	struct unix_socket_info *dest;

	if (sk->type != SOCK_DGRAM) {
		pr_err("trying to create non-DGRAM unconnected socket %d\n", sk->ino);
		return -EINVAL;
	}

	if (sk->path) {
		err = unix_bind_socket(sk, sock);
		if (err)
			return err;
	}

	if (!sk->peer_ino)
		return 0;

	if (sk->ino == sk->peer_ino)
		dest = sk;
	else {
		if (find_unix_socket(sk->peer_ino, (void **)&dest)) {
			pr_err("failed to find peer with inode %d\n", sk->peer_ino);
			return -EINVAL;
		}
	}

	return unix_connect_socket(dest, sock);
}

static int unix_create_connected_socket(struct unix_socket_info *dest)
{
	int err, sock;

	sock = socket(AF_UNIX, dest->type, 0);
	if (sock < 0) {
		pr_perror("failed to create socket");
		return -errno;
	}

	err = unix_connect_socket(dest, sock);

	if (err)
		close(sock);
	return err ? err :sock;
}

static int unix_create_connecting_socket(struct unix_socket_info *sk, int sock)
{
	if (!sk->peer) {
		pr_err("connecting socket without peer?\n");
		return -EINVAL;
	}

	return unix_connect_socket(sk->peer, sock);
}

static bool path_is_relative(const char *path)
{
	if (!path)
		return false;
	return path[0] != '/';
}

static int set_cwd(const char *cwd, char *cur_cwd, size_t size)
{
	int err;

	if (cur_cwd) {
		ssize_t bytes;

		snprintf(cur_cwd, size, "/proc/%d/cwd", getpid());
		bytes = readlink(cur_cwd, cur_cwd, size - 1);
		if (bytes < 0) {
			pr_perror("failed to read link %s\n", cur_cwd);
			return -errno;
		}
	}
	err = chdir(cwd);
	if (err) {
		pr_perror("failed to change working directory to %s", cwd);
		return -errno;
	}
	return 0;
}

static int unix_copy_rqueue(int source_fd, int dest_fd)
{
	int err, size, orig_peek_off;
	socklen_t tmp;
	void *data;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	orig_peek_off = 0;
	err = getsockopt(source_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (err < 0) {
		pr_perror("getsockopt failed");
		return -errno;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	err = getsockopt(source_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (err < 0) {
		pr_perror("getsockopt failed");
		return -errno;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a stream.
	 */
	data = malloc(size);
	if (!data) {
		pr_err("failed to allocate\n");
		return -ENOMEM;
	}

	/*
	 * Enable peek offset incrementation.
	 */
	err = setsockopt(source_fd, SOL_SOCKET, SO_PEEK_OFF, &err, sizeof(int));
	if (err < 0) {
		pr_perror("setsockopt fail");
		goto free_data;
	}

	while (1) {
		struct iovec iov = {
			.iov_base       = data,
			.iov_len        = size,
		};
		struct msghdr msg = {
			.msg_iov        = &iov,
			.msg_iovlen     = 1,
		};
		ssize_t received, sent;

		received = recvmsg(source_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (!received)
			/*
			 * It means, that peer has performed an
			 * orderly shutdown, so we're done.
			 */
			break;
		else if (received < 0) {
			if (errno == EAGAIN)
				break; /* we're done */
			pr_perror("recvmsg fail: error");
			err = -errno;
			break;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM truncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			err = -E2BIG;
			break;
		}

		iov.iov_len = received;

		sent = sendmsg(dest_fd, &msg, 0);
		if (sent < 0) {
			pr_perror("Failed to send packet");
			err = -errno;
			break;
		}
		if (sent != received) {
			pr_err("Sent skb trimmed to %ld/%ld\n", sent, received);
			err = -ENOSPC;
			break;
		}
	}

	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(source_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		err = -errno;
	}

free_data:
	free(data);
	return err;
}

static int unix_restore_rqueue(struct unix_socket_info *sk, int sock, int source_fd)
{
	int tmp_sock, err;

	if (!sk->rq_len)
	       return 0;

	/*
	 * Listening socket queue contains connection request.
	 * This is served by using UNIX_DIAG_ICONS by reconnecting to
	 * listening socket.
	 */
	if (sk->state == TCP_LISTEN)
	       return 0;

	if (sk->type != SOCK_DGRAM) {
		pr_err("restore of read queue for socket type %d is not supported yet\n", sk->type);
		return -ENOTSUP;
	}

	if (sk->state != TCP_CLOSE) {
		pr_err("restore of read queue for socket with state %d is not supported yet\n", sk->state);
		return -ENOTSUP;
	}

	tmp_sock = unix_create_connected_socket(sk);
	if (tmp_sock < 0)
		return tmp_sock;

	err = unix_copy_rqueue(source_fd, tmp_sock);

	close(tmp_sock);
	return err;
}

int unix_sk_file_open(const char *cwd, unsigned flags, int source_fd)
{
	struct unix_socket_info *sk;
	struct stat st;
	int err, sock;
	char cur_cwd[PATH_MAX];

	if (fstat(source_fd, &st)) {
		pr_perror("failed to stat fd %d", source_fd);
		return -errno;
	}

	err = find_unix_socket(st.st_ino, (void **)&sk);
	if (err) {
		pr_err("failed to find socket by inode %d: %d\n", st.st_ino, err);
		return err;
	}

	if (!unix_sk_is_supported(sk))
		return -ENOTSUP;

	if (sk->shutdown) {
		pr_err("sockets with shutdown state are not supported yet\n");
		return -ENOTSUP;
	}

	if (path_is_relative(sk->path)) {
		err = set_cwd(cwd, cur_cwd, PATH_MAX);
		if (err)
			return err;
	}

	sock = socket(AF_UNIX, sk->type | (flags & O_NONBLOCK), 0);
	if (sock < 0) {
		pr_perror("failed to create socket");
		return -errno;
	}

	if (sk->state == TCP_LISTEN)
		err = unix_listen_socket(sk, sock);
	else if (sk->state == TCP_ESTABLISHED)
		err = unix_create_connecting_socket(sk, sock);
	else
		err = unix_unconn_socket(sk, sock);

	if (path_is_relative(sk->path)) {
		int err2;

		err2 = set_cwd(cwd, NULL, 0);
		if (err2) {
			err = err2;
			goto close_sock;
		}
	}
	if (err)
		goto close_sock;

	err = unix_restore_rqueue(sk, sock, source_fd);

close_sock:
	if (err)
		close(sock);
	return err ? err : sock;
}

bool unix_sk_early_open(const char *cwd, unsigned flags, int source_fd)
{
	struct unix_socket_info *sk;
	struct stat st;
	int err;

	if (fstat(source_fd, &st)) {
		pr_perror("failed to stat fd %d", source_fd);
		return true;
	}

	err = find_unix_socket(st.st_ino, (void **)&sk);
	if (err) {
		pr_err("failed to find socket by inode %d: %d\n", st.st_ino, err);
		return true;
	}

	if (sk->state == TCP_LISTEN)
		return true;

	if (sk->path && (sk->type == SOCK_DGRAM))
		return true;

	return false;
}
