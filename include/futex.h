#ifndef __SPFS_SRC_FUTEX_H__
#define __SPFS_SRC_FUTEX_H__

struct timespec;

int futex_op(int *uaddr, int op, int val, const struct timespec *timeout,
			                 int *uaddr2, int val3);
int futex_wait(int *addr, int val, const struct timespec *timeout);
int futex_wake(int *addr);

#endif
