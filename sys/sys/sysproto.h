/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	Id: syscalls.master,v 1.33 1997/02/22 09:39:21 peter Exp 
 */

#ifndef _SYS_SYSPROTO_H_
#define	_SYS_SYSPROTO_H_

#include <sys/signal.h>

struct	nosys_args {
	int dummy;
};
struct	rexit_args {
	int rval;
};
struct	fork_args {
	int dummy;
};
struct	read_args {
	int fd;
	char * buf;
	u_int nbyte;
};
struct	write_args {
	int fd;
	char * buf;
	u_int nbyte;
};
struct	open_args {
	char * path;
	int flags;
	int mode;
};
struct	close_args {
	int fd;
};
struct	wait_args {
	int pid;
	int * status;
	int options;
	struct rusage * rusage;
};
struct	link_args {
	char * path;
	char * link;
};
struct	unlink_args {
	char * path;
};
struct	chdir_args {
	char * path;
};
struct	fchdir_args {
	int fd;
};
struct	mknod_args {
	char * path;
	int mode;
	int dev;
};
struct	chmod_args {
	char * path;
	int mode;
};
struct	chown_args {
	char * path;
	int uid;
	int gid;
};
struct	obreak_args {
	char * nsize;
};
struct	getfsstat_args {
	struct statfs * buf;
	long bufsize;
	int flags;
};
struct	getpid_args {
	int dummy;
};
struct	mount_args {
	char * type;
	char * path;
	int flags;
	caddr_t data;
};
struct	unmount_args {
	char * path;
	int flags;
};
struct	setuid_args {
	uid_t uid;
};
struct	getuid_args {
	int dummy;
};
struct	geteuid_args {
	int dummy;
};
struct	ptrace_args {
	int req;
	pid_t pid;
	caddr_t addr;
	int data;
};
struct	recvmsg_args {
	int s;
	struct msghdr * msg;
	int flags;
};
struct	sendmsg_args {
	int s;
	caddr_t msg;
	int flags;
};
struct	recvfrom_args {
	int s;
	caddr_t buf;
	size_t len;
	int flags;
	caddr_t from;
	int * fromlenaddr;
};
struct	accept_args {
	int s;
	caddr_t name;
	int * anamelen;
};
struct	getpeername_args {
	int fdes;
	caddr_t asa;
	int * alen;
};
struct	getsockname_args {
	int fdes;
	caddr_t asa;
	int * alen;
};
struct	access_args {
	char * path;
	int flags;
};
struct	chflags_args {
	char * path;
	int flags;
};
struct	fchflags_args {
	int fd;
	int flags;
};
struct	sync_args {
	int dummy;
};
struct	kill_args {
	int pid;
	int signum;
};
struct	getppid_args {
	int dummy;
};
struct	dup_args {
	u_int fd;
};
struct	pipe_args {
	int dummy;
};
struct	getegid_args {
	int dummy;
};
struct	profil_args {
	caddr_t samples;
	u_int size;
	u_int offset;
	u_int scale;
};
struct	ktrace_args {
	char * fname;
	int ops;
	int facs;
	int pid;
};
struct	sigaction_args {
	int signum;
	struct sigaction * nsa;
	struct sigaction * osa;
};
struct	getgid_args {
	int dummy;
};
struct	sigprocmask_args {
	int how;
	sigset_t mask;
};
struct	getlogin_args {
	char * namebuf;
	u_int namelen;
};
struct	setlogin_args {
	char * namebuf;
};
struct	acct_args {
	char * path;
};
struct	sigpending_args {
	int dummy;
};
struct	sigaltstack_args {
	struct sigaltstack * nss;
	struct sigaltstack * oss;
};
struct	ioctl_args {
	int fd;
	u_long com;
	caddr_t data;
};
struct	reboot_args {
	int opt;
};
struct	revoke_args {
	char * path;
};
struct	symlink_args {
	char * path;
	char * link;
};
struct	readlink_args {
	char * path;
	char * buf;
	int count;
};
struct	execve_args {
	char * fname;
	char ** argv;
	char ** envv;
};
struct	umask_args {
	int newmask;
};
struct	chroot_args {
	char * path;
};
struct	getpagesize_args {
	int dummy;
};
struct	msync_args {
	caddr_t addr;
	size_t len;
	int flags;
};
struct	vfork_args {
	int dummy;
};
struct	sbrk_args {
	int incr;
};
struct	sstk_args {
	int incr;
};
struct	ovadvise_args {
	int anom;
};
struct	munmap_args {
	caddr_t addr;
	size_t len;
};
struct	mprotect_args {
	caddr_t addr;
	size_t len;
	int prot;
};
struct	madvise_args {
	caddr_t addr;
	size_t len;
	int behav;
};
struct	mincore_args {
	caddr_t addr;
	size_t len;
	char * vec;
};
struct	getgroups_args {
	u_int gidsetsize;
	gid_t * gidset;
};
struct	setgroups_args {
	u_int gidsetsize;
	gid_t * gidset;
};
struct	getpgrp_args {
	int dummy;
};
struct	setpgid_args {
	int pid;
	int pgid;
};
struct	setitimer_args {
	u_int which;
	struct itimerval * itv;
	struct itimerval * oitv;
};
struct	owait_args {
	int dummy;
};
struct	swapon_args {
	char * name;
};
struct	getitimer_args {
	u_int which;
	struct itimerval * itv;
};
struct	getdtablesize_args {
	int dummy;
};
struct	dup2_args {
	u_int from;
	u_int to;
};
struct	fcntl_args {
	int fd;
	int cmd;
	int arg;
};
struct	select_args {
	int nd;
	fd_set * in;
	fd_set * ou;
	fd_set * ex;
	struct timeval * tv;
};
struct	fsync_args {
	int fd;
};
struct	setpriority_args {
	int which;
	int who;
	int prio;
};
struct	socket_args {
	int domain;
	int type;
	int protocol;
};
struct	connect_args {
	int s;
	caddr_t name;
	int namelen;
};
struct	getpriority_args {
	int which;
	int who;
};
struct	sigreturn_args {
	struct sigcontext * sigcntxp;
};
struct	bind_args {
	int s;
	caddr_t name;
	int namelen;
};
struct	setsockopt_args {
	int s;
	int level;
	int name;
	caddr_t val;
	int valsize;
};
struct	listen_args {
	int s;
	int backlog;
};
struct	sigsuspend_args {
	sigset_t mask;
};
struct	gettimeofday_args {
	struct timeval * tp;
	struct timezone * tzp;
};
struct	getrusage_args {
	int who;
	struct rusage * rusage;
};
struct	getsockopt_args {
	int s;
	int level;
	int name;
	caddr_t val;
	int * avalsize;
};
struct	readv_args {
	int fd;
	struct iovec * iovp;
	u_int iovcnt;
};
struct	writev_args {
	int fd;
	struct iovec * iovp;
	u_int iovcnt;
};
struct	settimeofday_args {
	struct timeval * tv;
	struct timezone * tzp;
};
struct	fchown_args {
	int fd;
	int uid;
	int gid;
};
struct	fchmod_args {
	int fd;
	int mode;
};
struct	setreuid_args {
	int ruid;
	int euid;
};
struct	setregid_args {
	int rgid;
	int egid;
};
struct	rename_args {
	char * from;
	char * to;
};
struct	flock_args {
	int fd;
	int how;
};
struct	mkfifo_args {
	char * path;
	int mode;
};
struct	sendto_args {
	int s;
	caddr_t buf;
	size_t len;
	int flags;
	caddr_t to;
	int tolen;
};
struct	shutdown_args {
	int s;
	int how;
};
struct	socketpair_args {
	int domain;
	int type;
	int protocol;
	int * rsv;
};
struct	mkdir_args {
	char * path;
	int mode;
};
struct	rmdir_args {
	char * path;
};
struct	utimes_args {
	char * path;
	struct timeval * tptr;
};
struct	adjtime_args {
	struct timeval * delta;
	struct timeval * olddelta;
};
struct	ogethostid_args {
	int dummy;
};
struct	setsid_args {
	int dummy;
};
struct	quotactl_args {
	char * path;
	int cmd;
	int uid;
	caddr_t arg;
};
struct	oquota_args {
	int dummy;
};
#ifdef NFS
struct	nfssvc_args {
	int flag;
	caddr_t argp;
};
#else
#endif
struct	statfs_args {
	char * path;
	struct statfs * buf;
};
struct	fstatfs_args {
	int fd;
	struct statfs * buf;
};
#if defined(NFS) && !defined (NFS_NOSERVER)
struct	getfh_args {
	char * fname;
	struct fhandle * fhp;
};
#else
#endif
struct	getdomainname_args {
	char * domainname;
	int len;
};
struct	setdomainname_args {
	char * domainname;
	int len;
};
struct	uname_args {
	struct utsname * name;
};
struct	sysarch_args {
	int op;
	char * parms;
};
struct	rtprio_args {
	int function;
	pid_t pid;
	struct rtprio * rtp;
};
struct	semsys_args {
	int which;
	int a2;
	int a3;
	int a4;
	int a5;
};
struct	msgsys_args {
	int which;
	int a2;
	int a3;
	int a4;
	int a5;
	int a6;
};
struct	shmsys_args {
	int which;
	int a2;
	int a3;
	int a4;
};
struct	ntp_adjtime_args {
	struct timex * tp;
};
struct	setgid_args {
	gid_t gid;
};
struct	setegid_args {
	gid_t egid;
};
struct	seteuid_args {
	uid_t euid;
};
#ifdef LFS
struct	lfs_bmapv_args {
	struct fsid ** fsidp;
	struct block_info * blkiov;
	int blkcnt;
};
struct	lfs_markv_args {
	struct fsid ** fsidp;
	struct block_info * blkiov;
	int blkcnt;
};
struct	lfs_segclean_args {
	struct fsid ** fsidp;
	u_long segment;
};
struct	lfs_segwait_args {
	struct fsid ** fsidp;
	struct timeval * tv;
};
#else
#endif
struct	stat_args {
	char * path;
	struct stat * ub;
};
struct	fstat_args {
	int fd;
	struct stat * sb;
};
struct	lstat_args {
	char * path;
	struct stat * ub;
};
struct	pathconf_args {
	char * path;
	int name;
};
struct	fpathconf_args {
	int fd;
	int name;
};
struct	__getrlimit_args {
	u_int which;
	struct orlimit * rlp;
};
struct	__setrlimit_args {
	u_int which;
	struct orlimit * rlp;
};
struct	getdirentries_args {
	int fd;
	char * buf;
	u_int count;
	long * basep;
};
struct	mmap_args {
	caddr_t addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	long pad;
	off_t pos;
};
struct	lseek_args {
	int fd;
	int pad;
	off_t offset;
	int whence;
};
struct	truncate_args {
	char * path;
	int pad;
	off_t length;
};
struct	ftruncate_args {
	int fd;
	int pad;
	off_t length;
};
struct	sysctl_args {
	int * name;
	u_int namelen;
	void * old;
	size_t * oldlenp;
	void * new;
	size_t newlen;
};
struct	mlock_args {
	caddr_t addr;
	size_t len;
};
struct	munlock_args {
	caddr_t addr;
	size_t len;
};
struct	utrace_args {
	caddr_t addr;
	size_t len;
};
struct	undelete_args {
	char * path;
};
struct	__semctl_args {
	int semid;
	int semnum;
	int cmd;
	union semun * arg;
};
struct	semget_args {
	key_t key;
	int nsems;
	int semflg;
};
struct	semop_args {
	int semid;
	struct sembuf * sops;
	u_int nsops;
};
struct	semconfig_args {
	int flag;
};
struct	msgctl_args {
	int msqid;
	int cmd;
	struct msqid_ds * buf;
};
struct	msgget_args {
	key_t key;
	int msgflg;
};
struct	msgsnd_args {
	int msqid;
	void * msgp;
	size_t msgsz;
	int msgflg;
};
struct	msgrcv_args {
	int msqid;
	void * msgp;
	size_t msgsz;
	long msgtyp;
	int msgflg;
};
struct	shmat_args {
	int shmid;
	void * shmaddr;
	int shmflg;
};
struct	shmctl_args {
	int shmid;
	int cmd;
	struct shmid_ds * buf;
};
struct	shmdt_args {
	void * shmaddr;
};
struct	shmget_args {
	key_t key;
	int size;
	int shmflg;
};
struct	minherit_args {
	caddr_t addr;
	size_t len;
	int inherit;
};
struct	rfork_args {
	int flags;
};
int	nosys __P((struct proc *, struct nosys_args *, int []));
void	exit __P((struct proc *, struct rexit_args *, int [])) __dead2;
int	fork __P((struct proc *, struct fork_args *, int []));
int	read __P((struct proc *, struct read_args *, int []));
int	write __P((struct proc *, struct write_args *, int []));
int	open __P((struct proc *, struct open_args *, int []));
int	close __P((struct proc *, struct close_args *, int []));
int	wait4 __P((struct proc *, struct wait_args *, int []));
int	link __P((struct proc *, struct link_args *, int []));
int	unlink __P((struct proc *, struct unlink_args *, int []));
int	chdir __P((struct proc *, struct chdir_args *, int []));
int	fchdir __P((struct proc *, struct fchdir_args *, int []));
int	mknod __P((struct proc *, struct mknod_args *, int []));
int	chmod __P((struct proc *, struct chmod_args *, int []));
int	chown __P((struct proc *, struct chown_args *, int []));
int	obreak __P((struct proc *, struct obreak_args *, int []));
int	getfsstat __P((struct proc *, struct getfsstat_args *, int []));
int	getpid __P((struct proc *, struct getpid_args *, int []));
int	mount __P((struct proc *, struct mount_args *, int []));
int	unmount __P((struct proc *, struct unmount_args *, int []));
int	setuid __P((struct proc *, struct setuid_args *, int []));
int	getuid __P((struct proc *, struct getuid_args *, int []));
int	geteuid __P((struct proc *, struct geteuid_args *, int []));
int	ptrace __P((struct proc *, struct ptrace_args *, int []));
int	recvmsg __P((struct proc *, struct recvmsg_args *, int []));
int	sendmsg __P((struct proc *, struct sendmsg_args *, int []));
int	recvfrom __P((struct proc *, struct recvfrom_args *, int []));
int	accept __P((struct proc *, struct accept_args *, int []));
int	getpeername __P((struct proc *, struct getpeername_args *, int []));
int	getsockname __P((struct proc *, struct getsockname_args *, int []));
int	access __P((struct proc *, struct access_args *, int []));
int	chflags __P((struct proc *, struct chflags_args *, int []));
int	fchflags __P((struct proc *, struct fchflags_args *, int []));
int	sync __P((struct proc *, struct sync_args *, int []));
int	kill __P((struct proc *, struct kill_args *, int []));
int	getppid __P((struct proc *, struct getppid_args *, int []));
int	dup __P((struct proc *, struct dup_args *, int []));
int	pipe __P((struct proc *, struct pipe_args *, int []));
int	getegid __P((struct proc *, struct getegid_args *, int []));
int	profil __P((struct proc *, struct profil_args *, int []));
int	ktrace __P((struct proc *, struct ktrace_args *, int []));
int	sigaction __P((struct proc *, struct sigaction_args *, int []));
int	getgid __P((struct proc *, struct getgid_args *, int []));
int	sigprocmask __P((struct proc *, struct sigprocmask_args *, int []));
int	getlogin __P((struct proc *, struct getlogin_args *, int []));
int	setlogin __P((struct proc *, struct setlogin_args *, int []));
int	acct __P((struct proc *, struct acct_args *, int []));
int	sigpending __P((struct proc *, struct sigpending_args *, int []));
int	sigaltstack __P((struct proc *, struct sigaltstack_args *, int []));
int	ioctl __P((struct proc *, struct ioctl_args *, int []));
int	reboot __P((struct proc *, struct reboot_args *, int []));
int	revoke __P((struct proc *, struct revoke_args *, int []));
int	symlink __P((struct proc *, struct symlink_args *, int []));
int	readlink __P((struct proc *, struct readlink_args *, int []));
int	execve __P((struct proc *, struct execve_args *, int []));
int	umask __P((struct proc *, struct umask_args *, int []));
int	chroot __P((struct proc *, struct chroot_args *, int []));
int	msync __P((struct proc *, struct msync_args *, int []));
int	vfork __P((struct proc *, struct vfork_args *, int []));
int	sbrk __P((struct proc *, struct sbrk_args *, int []));
int	sstk __P((struct proc *, struct sstk_args *, int []));
int	ovadvise __P((struct proc *, struct ovadvise_args *, int []));
int	munmap __P((struct proc *, struct munmap_args *, int []));
int	mprotect __P((struct proc *, struct mprotect_args *, int []));
int	madvise __P((struct proc *, struct madvise_args *, int []));
int	mincore __P((struct proc *, struct mincore_args *, int []));
int	getgroups __P((struct proc *, struct getgroups_args *, int []));
int	setgroups __P((struct proc *, struct setgroups_args *, int []));
int	getpgrp __P((struct proc *, struct getpgrp_args *, int []));
int	setpgid __P((struct proc *, struct setpgid_args *, int []));
int	setitimer __P((struct proc *, struct setitimer_args *, int []));
int	swapon __P((struct proc *, struct swapon_args *, int []));
int	getitimer __P((struct proc *, struct getitimer_args *, int []));
int	getdtablesize __P((struct proc *, struct getdtablesize_args *, int []));
int	dup2 __P((struct proc *, struct dup2_args *, int []));
int	fcntl __P((struct proc *, struct fcntl_args *, int []));
int	select __P((struct proc *, struct select_args *, int []));
int	fsync __P((struct proc *, struct fsync_args *, int []));
int	setpriority __P((struct proc *, struct setpriority_args *, int []));
int	socket __P((struct proc *, struct socket_args *, int []));
int	connect __P((struct proc *, struct connect_args *, int []));
int	getpriority __P((struct proc *, struct getpriority_args *, int []));
int	sigreturn __P((struct proc *, struct sigreturn_args *, int []));
int	bind __P((struct proc *, struct bind_args *, int []));
int	setsockopt __P((struct proc *, struct setsockopt_args *, int []));
int	listen __P((struct proc *, struct listen_args *, int []));
int	sigsuspend __P((struct proc *, struct sigsuspend_args *, int []));
int	gettimeofday __P((struct proc *, struct gettimeofday_args *, int []));
int	getrusage __P((struct proc *, struct getrusage_args *, int []));
int	getsockopt __P((struct proc *, struct getsockopt_args *, int []));
int	readv __P((struct proc *, struct readv_args *, int []));
int	writev __P((struct proc *, struct writev_args *, int []));
int	settimeofday __P((struct proc *, struct settimeofday_args *, int []));
int	fchown __P((struct proc *, struct fchown_args *, int []));
int	fchmod __P((struct proc *, struct fchmod_args *, int []));
int	setreuid __P((struct proc *, struct setreuid_args *, int []));
int	setregid __P((struct proc *, struct setregid_args *, int []));
int	rename __P((struct proc *, struct rename_args *, int []));
int	flock __P((struct proc *, struct flock_args *, int []));
int	mkfifo __P((struct proc *, struct mkfifo_args *, int []));
int	sendto __P((struct proc *, struct sendto_args *, int []));
int	shutdown __P((struct proc *, struct shutdown_args *, int []));
int	socketpair __P((struct proc *, struct socketpair_args *, int []));
int	mkdir __P((struct proc *, struct mkdir_args *, int []));
int	rmdir __P((struct proc *, struct rmdir_args *, int []));
int	utimes __P((struct proc *, struct utimes_args *, int []));
int	adjtime __P((struct proc *, struct adjtime_args *, int []));
int	setsid __P((struct proc *, struct setsid_args *, int []));
int	quotactl __P((struct proc *, struct quotactl_args *, int []));
#ifdef NFS
int	nfssvc __P((struct proc *, struct nfssvc_args *, int []));
#else
#endif
int	statfs __P((struct proc *, struct statfs_args *, int []));
int	fstatfs __P((struct proc *, struct fstatfs_args *, int []));
#if defined(NFS) && !defined (NFS_NOSERVER)
int	getfh __P((struct proc *, struct getfh_args *, int []));
#else
#endif
int	getdomainname __P((struct proc *, struct getdomainname_args *, int []));
int	setdomainname __P((struct proc *, struct setdomainname_args *, int []));
int	uname __P((struct proc *, struct uname_args *, int []));
int	sysarch __P((struct proc *, struct sysarch_args *, int []));
int	rtprio __P((struct proc *, struct rtprio_args *, int []));
int	semsys __P((struct proc *, struct semsys_args *, int []));
int	msgsys __P((struct proc *, struct msgsys_args *, int []));
int	shmsys __P((struct proc *, struct shmsys_args *, int []));
int	ntp_adjtime __P((struct proc *, struct ntp_adjtime_args *, int []));
int	setgid __P((struct proc *, struct setgid_args *, int []));
int	setegid __P((struct proc *, struct setegid_args *, int []));
int	seteuid __P((struct proc *, struct seteuid_args *, int []));
#ifdef LFS
int	lfs_bmapv __P((struct proc *, struct lfs_bmapv_args *, int []));
int	lfs_markv __P((struct proc *, struct lfs_markv_args *, int []));
int	lfs_segclean __P((struct proc *, struct lfs_segclean_args *, int []));
int	lfs_segwait __P((struct proc *, struct lfs_segwait_args *, int []));
#else
#endif
int	stat __P((struct proc *, struct stat_args *, int []));
int	fstat __P((struct proc *, struct fstat_args *, int []));
int	lstat __P((struct proc *, struct lstat_args *, int []));
int	pathconf __P((struct proc *, struct pathconf_args *, int []));
int	fpathconf __P((struct proc *, struct fpathconf_args *, int []));
int	getrlimit __P((struct proc *, struct __getrlimit_args *, int []));
int	setrlimit __P((struct proc *, struct __setrlimit_args *, int []));
int	getdirentries __P((struct proc *, struct getdirentries_args *, int []));
int	mmap __P((struct proc *, struct mmap_args *, int []));
int	lseek __P((struct proc *, struct lseek_args *, int []));
int	truncate __P((struct proc *, struct truncate_args *, int []));
int	ftruncate __P((struct proc *, struct ftruncate_args *, int []));
int	__sysctl __P((struct proc *, struct sysctl_args *, int []));
int	mlock __P((struct proc *, struct mlock_args *, int []));
int	munlock __P((struct proc *, struct munlock_args *, int []));
int	utrace __P((struct proc *, struct utrace_args *, int []));
int	undelete __P((struct proc *, struct undelete_args *, int []));
int	lkmnosys __P((struct proc *, struct nosys_args *, int []));
int	__semctl __P((struct proc *, struct __semctl_args *, int []));
int	semget __P((struct proc *, struct semget_args *, int []));
int	semop __P((struct proc *, struct semop_args *, int []));
int	semconfig __P((struct proc *, struct semconfig_args *, int []));
int	msgctl __P((struct proc *, struct msgctl_args *, int []));
int	msgget __P((struct proc *, struct msgget_args *, int []));
int	msgsnd __P((struct proc *, struct msgsnd_args *, int []));
int	msgrcv __P((struct proc *, struct msgrcv_args *, int []));
int	shmat __P((struct proc *, struct shmat_args *, int []));
int	shmctl __P((struct proc *, struct shmctl_args *, int []));
int	shmdt __P((struct proc *, struct shmdt_args *, int []));
int	shmget __P((struct proc *, struct shmget_args *, int []));
int	minherit __P((struct proc *, struct minherit_args *, int []));
int	rfork __P((struct proc *, struct rfork_args *, int []));

#ifdef COMPAT_43

struct	ocreat_args {
	char * path;
	int mode;
};
struct	olseek_args {
	int fd;
	long offset;
	int whence;
};
struct	ostat_args {
	char * path;
	struct ostat * ub;
};
struct	olstat_args {
	char * path;
	struct ostat * ub;
};
struct	ofstat_args {
	int fd;
	struct ostat * sb;
};
struct	getkerninfo_args {
	int op;
	char * where;
	int * size;
	int arg;
};
struct	ommap_args {
	caddr_t addr;
	int len;
	int prot;
	int flags;
	int fd;
	long pos;
};
struct	gethostname_args {
	char * hostname;
	u_int len;
};
struct	sethostname_args {
	char * hostname;
	u_int len;
};
struct	osend_args {
	int s;
	caddr_t buf;
	int len;
	int flags;
};
struct	orecv_args {
	int s;
	caddr_t buf;
	int len;
	int flags;
};
struct	osigvec_args {
	int signum;
	struct sigvec * nsv;
	struct sigvec * osv;
};
struct	osigblock_args {
	int mask;
};
struct	osigsetmask_args {
	int mask;
};
struct	osigstack_args {
	struct sigstack * nss;
	struct sigstack * oss;
};
struct	orecvmsg_args {
	int s;
	struct omsghdr * msg;
	int flags;
};
struct	osendmsg_args {
	int s;
	caddr_t msg;
	int flags;
};
struct	otruncate_args {
	char * path;
	long length;
};
struct	oftruncate_args {
	int fd;
	long length;
};
struct	ogetpeername_args {
	int fdes;
	caddr_t asa;
	int * alen;
};
struct	osethostid_args {
	long hostid;
};
struct	ogetrlimit_args {
	u_int which;
	struct ogetrlimit * rlp;
};
struct	osetrlimit_args {
	u_int which;
	struct ogetrlimit * rlp;
};
struct	okillpg_args {
	int pgid;
	int signum;
};
#ifdef NFS
#else
#endif
struct	ogetdirentries_args {
	int fd;
	char * buf;
	u_int count;
	long * basep;
};
#if defined(NFS) && !defined (NFS_NOSERVER)
#else
#endif
#ifdef LFS
#else
#endif
int	ocreat __P((struct proc *, struct ocreat_args *, int []));
int	olseek __P((struct proc *, struct olseek_args *, int []));
int	ostat __P((struct proc *, struct ostat_args *, int []));
int	olstat __P((struct proc *, struct olstat_args *, int []));
int	ofstat __P((struct proc *, struct ofstat_args *, int []));
int	ogetkerninfo __P((struct proc *, struct getkerninfo_args *, int []));
int	ogetpagesize __P((struct proc *, struct getpagesize_args *, int []));
int	ommap __P((struct proc *, struct ommap_args *, int []));
int	owait __P((struct proc *, struct owait_args *, int []));
int	ogethostname __P((struct proc *, struct gethostname_args *, int []));
int	osethostname __P((struct proc *, struct sethostname_args *, int []));
int	oaccept __P((struct proc *, struct accept_args *, int []));
int	osend __P((struct proc *, struct osend_args *, int []));
int	orecv __P((struct proc *, struct orecv_args *, int []));
int	osigvec __P((struct proc *, struct osigvec_args *, int []));
int	osigblock __P((struct proc *, struct osigblock_args *, int []));
int	osigsetmask __P((struct proc *, struct osigsetmask_args *, int []));
int	osigstack __P((struct proc *, struct osigstack_args *, int []));
int	orecvmsg __P((struct proc *, struct orecvmsg_args *, int []));
int	osendmsg __P((struct proc *, struct osendmsg_args *, int []));
int	orecvfrom __P((struct proc *, struct recvfrom_args *, int []));
int	otruncate __P((struct proc *, struct otruncate_args *, int []));
int	oftruncate __P((struct proc *, struct oftruncate_args *, int []));
int	ogetpeername __P((struct proc *, struct ogetpeername_args *, int []));
int	ogethostid __P((struct proc *, struct ogethostid_args *, int []));
int	osethostid __P((struct proc *, struct osethostid_args *, int []));
int	ogetrlimit __P((struct proc *, struct ogetrlimit_args *, int []));
int	osetrlimit __P((struct proc *, struct osetrlimit_args *, int []));
int	okillpg __P((struct proc *, struct okillpg_args *, int []));
int	oquota __P((struct proc *, struct oquota_args *, int []));
int	ogetsockname __P((struct proc *, struct getsockname_args *, int []));
int	ogetdirentries __P((struct proc *, struct ogetdirentries_args *, int []));

#endif /* COMPAT_43 */

#endif /* !_SYS_SYSPROTO_H_ */
