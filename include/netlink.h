#ifndef __SPFS_NETLINK_H_
#define __SPFS_NETLINK_H_

#define CR_NLMSG_SEQ            24680   /* arbitrary chosen */

struct nlmsghdr;

extern int do_rtnl_req(int nl, void *req, int size,
		       int (*receive_callback)(struct nlmsghdr *h, void *),
				               int (*error_callback)(int err, void *), void *);

/*TODO look like this function is not needed */
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type,
		     const void *data, int alen);

#define NLMSG_TAIL(nmsg) \
	        ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#endif
