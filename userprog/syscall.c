#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "include/threads/init.h"
#include "include/threads/synch.h"
#include "include/threads/malloc.h"
#include "include/filesys/filesys.h"
#include "include/filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static bool compare_by_fd(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
	fd_cnt = 3;
}


// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if (!is_user_vaddr(addr)) {
		exit(-1);
		//printf("address is not valid\n");
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	//printf("system call\n");

	// TODO: Your implementation goes here.
	// HS 2-2-1. syscall_handler 구현
	memcpy(&thread_current()->tf, f, sizeof(struct intr_frame));

	// 인터럽트 f에서 레지스터에 대한 정보 R을 가져오고, 해당 시스템 콜(f->R.rax)을 switch문으로 호출
	// argument가 필요한 시스템 콜의 경우, f->R.rdi가 유저 메모리 영역(0~KERN_BASE)에 해당하는지를 확인
	switch (f->R.rax) {
		case SYS_HALT:
			printf("halt\n");
			break;
		case SYS_EXIT:
			//printf("exit\n");
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			printf("fork\n");
			break;
		case SYS_EXEC:
			printf("exec\n");
			break;
		case SYS_WAIT:
			printf("wait\n");
			break;
		case SYS_CREATE:
			check_address(f->R.rdi);
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			printf("remove\n");
			break;
		case SYS_OPEN:
			//printf("open\n");
			check_address(f->R.rdi);
      f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			printf("filesize\n");
			break;
		case SYS_READ:
			printf("read\n");
			break;
		case SYS_WRITE:
			check_address(f->R.rsi);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			printf("seek\n");
			break;
		case SYS_TELL:
			printf("tell\n");
			break;
		case SYS_CLOSE:
			//printf("close\n");
			close(f->R.rdi);
			break;
		default:
			thread_exit();
			break;
	}
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	thread_current()->exit_status = status;
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

bool
create(const char *file, unsigned initial_size) {
	bool result;

  if (file == NULL)
    exit(-1);
	lock_acquire(&filesys_lock);
	result = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return result;
}

int
open(const char * file) {
	if (file == NULL)
		exit(-1);
	lock_acquire(&filesys_lock);
	struct file * open_file = filesys_open(file);
	lock_release(&filesys_lock);

	if (open_file == NULL) { // file open error
		return -1;
	} else { // file open complete!
		struct thread * curr = thread_current();
		struct fd_elem * new_fd = malloc(sizeof(struct fd_elem));
		
		// fd를 정하는 과정 - 일단은 fd 계속 증가
		new_fd->fd = fd_cnt;
		fd_cnt++;
		new_fd->file_ptr = open_file;

		list_insert_ordered(&curr->fd_list, &new_fd->elem, compare_by_fd, NULL);
		return new_fd->fd;
	}
}

int 
write (int fd, const void *buffer, unsigned size) {
    int write_result = 0;
    lock_acquire(&filesys_lock);
    if (fd == 1) {
        putbuf(buffer, size);
        write_result = size;
    }
    else {
        // if (process_get_file(fd) != NULL) {
           // write_result = file_write(process_get_file(fd), buffer, size);
        // }
        // else{
//            write_result = -1;
//        }
    }
    lock_release(&filesys_lock);
    return write_result;
}

// JH fd가 너무 많아서 구별해주려고 parameter이름 arg_fd로 한거임....
// 좋은 이름 추천 받아요
void
close (int arg_fd) {
	struct thread * curr = thread_current();
	struct list_elem * e;
	struct fd_elem * close_fd = NULL;
	bool find_fd = false;

	for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct fd_elem * tmp_fd = list_entry(e, struct fd_elem, elem);
		if (arg_fd == tmp_fd->fd) { // closing 할 fd 발견!
			find_fd = true;
			close_fd = tmp_fd;
			break;
		}
	}
	if (find_fd) {
		// fd_list에서 close 하고자 하는 fd_elem 제거
		list_remove(e);
		// 해당 fd에 연결되어 있는 open file close
		lock_acquire(&filesys_lock);
		file_close(close_fd->file_ptr);
		lock_release(&filesys_lock);
		// malloc()으로 만들어줬던 fd_elem free
		free(close_fd);
	} else {
		exit(-1);
	}
	
}

static bool compare_by_fd(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	int fd_a = list_entry(a, struct fd_elem, elem)->fd;
	int fd_b = list_entry(b, struct fd_elem, elem)->fd;
	return (fd_a < fd_b);
}