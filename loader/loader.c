/*
 * Loader Implementation
 *
 * 2018, Operating Systems
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
#include <errno.h>

#include "exec_parser.h"

static so_exec_t *exec;
static int fd;

void so_sigaction(int sig_no, siginfo_t *sig_info, void *context)
{
	if(sig_no != SIGSEGV) 
		return;
	
	if (sig_info == NULL)
		exit(EXIT_FAILURE);

	int page_fault_addr = (int)sig_info->si_addr;
	void *prev_handler;

	for (int i = 0; i < exec->segments_no; i++) {
		so_seg_t *segment = (exec->segments) + i;


		if (segment->vaddr <= page_fault_addr &&
			page_fault_addr < segment->vaddr + segment->mem_size) {
			if (segment->data == NULL) {
				int possible_pages = segment->mem_size / getpagesize();

				segment->data = (void *) malloc(possible_pages * sizeof(char));
				// memset(segment->data, 0, possible_pages * sizeof(char));
			}

			int page_index = (page_fault_addr - segment->vaddr) / getpagesize();
			uintptr_t page_addr = page_index * getpagesize();

			if (((char *)(segment->data))[page_index] == 1) {
				fprintf(stderr, "Invalid permissions\n");
				signal(SIGSEGV, prev_handler);
				// raise(SIGSEGV);
			}

			char *mapped_addr = mmap((void *)(segment->vaddr + page_addr), getpagesize(), PROT_WRITE,
				MAP_SHARED | MAP_FIXED | MAP_ANON, -1, 0);

			if (mapped_addr == MAP_FAILED) {
				fprintf(stderr, "Error mapping page.\nerror numner: %d\n", errno);
				exit(EXIT_FAILURE);
			}

			((char *)(segment->data))[page_index] = 1;

			if (page_addr < segment->file_size) {
				lseek(fd, segment->offset + page_addr, SEEK_SET);

				
				int bytes_read;
				if((segment->file_size - page_addr) < getpagesize()) 
					bytes_read = read(fd, (void *) mapped_addr, segment->file_size - page_addr);
				else 
					bytes_read = read(fd, (void *) mapped_addr, getpagesize());

				if (bytes_read == -1) {
					fprintf(stderr, "Error reading from file\n");
					exit(EXIT_FAILURE);
				}
			}

			mprotect(mapped_addr, getpagesize(), PROT_NONE);

			int perm_flags = 0;

			if ((segment->perm & PERM_R) != 0)
				perm_flags |= PROT_READ;
			if ((segment->perm & PERM_W) != 0)
				perm_flags |= PROT_WRITE;
			if ((segment->perm & PERM_X) != 0)
				perm_flags |= PROT_EXEC;

			mprotect(mapped_addr, getpagesize(), perm_flags);
			return;
		}
	}

	fprintf(stderr, "Seg Fault outside of Exec segments\n");
	signal(SIGSEGV, prev_handler);
}

int so_init_loader(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = so_sigaction;
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
