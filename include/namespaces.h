#ifndef __SPFS_NAMESPACES_H_
#define __SPFS_NAMESPACES_H_

enum {
	NS_UTS,
	NS_MNT,
	NS_NET,
	NS_PID,
	NS_USER,
	NS_MAX
};

#define NS_UTS_MASK	(1 << NS_UTS)
#define NS_MNT_MASK	(1 << NS_MNT)
#define NS_NET_MASK	(1 << NS_NET)
#define NS_PID_MASK	(1 << NS_PID)
#define NS_USER_MASK	(1 << NS_USER)

#define NS_ALL_MASK	NS_UTS_MASK | NS_MNT_MASK | NS_NET_MASK |	\
			NS_PID_MASK | NS_USER_MASK

int open_ns(pid_t pid, const char *ns);
int set_namespaces(int *ns_fds, unsigned ns_mask);
int change_namespaces(pid_t pid, unsigned ns_mask, int *orig_ns_fds[]);
int close_namespaces(int *ns_fds);
int open_namespaces(pid_t pid, int *ns_fds);

#endif
