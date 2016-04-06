#ifndef __SPFS_IPC_H_
#define __SPFS_IPC_H_

int report_status(int pipe, int res);
int kill_child_and_collect(int pid);
int wait_child_report(int pipe);

#endif
