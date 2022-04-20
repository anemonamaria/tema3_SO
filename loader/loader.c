/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int fd;

void so_sa_sigaction(int signum, siginfo_t *info, void *context)
{
	if (signum != SIGSEGV) 
		return;
	
	if (info == NULL)
		return;

	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t *seg = (exec->segments) + i;
		int s_vaddr = seg->vaddr;

		if (s_vaddr <= (int)info->si_addr &&
			(int)info->si_addr < s_vaddr + seg->mem_size) {
			if (seg->data == NULL) {
				int page = ((int)info->si_addr + s_vaddr) / getpagesize();
				seg->data = (void *) calloc(page, sizeof(char));
			}

			// retin adresa de start
			int page_start = ((int)info->si_addr - s_vaddr) / getpagesize();

			if (((char *)(seg->data))[page_start] != 1) {
				((char *)(seg->data))[page_start] = 1;
			} else {
				signal(SIGSEGV, NULL);
				return;
			}
			// mapez pagina
			char *mmap_ret = mmap((void *)(s_vaddr + page_start * getpagesize()), 
				getpagesize(), PROT_WRITE, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);

			if (mmap_ret == MAP_FAILED) {
				return;
			}

			int size = seg->file_size - page_start * getpagesize();
			if (size > 0) {
				int ret = lseek(fd, seg->offset + page_start * getpagesize(),
						SEEK_SET);
				if (ret < 0)
					return;
				
				int read_ret;
				if(size - getpagesize() < 0)  // citesc in memorie
					read_ret = read(fd, (void *) mmap_ret, size);
				else 
					read_ret = read(fd, (void *) mmap_ret, getpagesize());

				if (read_ret == -1) {
					return;
				}
			}

			mprotect(mmap_ret, getpagesize(), seg->perm);
			return;
		}
	}

	signal(SIGSEGV, NULL);
}

int so_init_loader(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = so_sa_sigaction;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	
	int ret = sigaction(SIGSEGV, &sa, NULL);
	if (ret < 0)
		return -1;

	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY, 0644);
	if (fd < 0)
		return -1;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	close(fd);

	return -1;
}
