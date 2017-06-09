#ifndef __SPFS_NAMESPACES_H_
#define __SPFS_NAMESPACES_H_

typedef enum {
	NS_UTS,
	NS_MNT,
	NS_NET,
	NS_PID,
	NS_USER,
	NS_MAX
} nstype_t;

#define NS_UTS_MASK	(1 << NS_UTS)
#define NS_MNT_MASK	(1 << NS_MNT)
#define NS_NET_MASK	(1 << NS_NET)
#define NS_PID_MASK	(1 << NS_PID)
#define NS_USER_MASK	(1 << NS_USER)

#define NS_ALL_MASK	NS_UTS_MASK | NS_MNT_MASK | NS_NET_MASK |	\
			NS_PID_MASK | NS_USER_MASK

int open_ns(pid_t pid, nstype_t ns_type);
int set_ns(int ns_fd);

int set_namespaces(const int *ns_fds, unsigned ns_mask);
int close_namespaces(int *ns_fds);
int open_namespaces(pid_t pid, int *ns_fds);

#endif
