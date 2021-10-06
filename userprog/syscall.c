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

#include "devices/input.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
static bool compare_by_fd(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
static struct file * find_file_by_fd (int fd);

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
// JH 또 user가 전달한 pointer가 mapping 되지 않았을 수도 있음으로 이것도 체크
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if (!is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4, addr))
		exit(-1);
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
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			check_address(f->R.rdi);
			fork(f->R.rdi);
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
			check_address(f->R.rdi);
      f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_address(f->R.rsi);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
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

pid_t fork (const char *thread_name){
    struct intr_frame *user_tf = &thread_current()->tf;
    pid_t child_pid = (pid_t) process_fork(thread_name, user_tf);
	msg("process_fork success\n");
	struct thread * child = NULL;

	for (struct list_elem * e = list_begin(&thread_current()->child_list); e != list_end(&thread_current()->child_list); e = list_next(e)) {
		child = list_entry(e, struct thread, child_elem);
		if (child->tid == child_pid) {
			sema_down(&child->load_sema);
			break;
		}
	}
	msg("sema_down success\n");
    return child_pid;
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
filesize (int fd) {
	struct file * size_check_file_ptr = find_file_by_fd(fd);
	if (size_check_file_ptr != NULL)
		return file_length(size_check_file_ptr);
	else
		exit(-1);
	// for (struct list_elem * e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e)) {
	// 	struct fd_elem * tmp_fd = list_entry(e, struct fd_elem, elem);
	// 	if (fd == tmp_fd->fd) { // read 할 fd 발견!
	// 		//Warning : 그냥 read, write 개념이 아니라 값을 찾는거라 lock 안 걸었는데 문제가 되려나...?
	// 		return file_length(tmp_fd->file_ptr);
	// 	}
	// }
	// exit(-1);
}

int
read (int fd, const void *buffer, unsigned size) {
	int actually_read_byte = 0;
	
	if (fd == 0) { // STDIN
		lock_acquire(&filesys_lock);
		actually_read_byte = input_getc();
		lock_release(&filesys_lock);
		return actually_read_byte;
	} else if (fd >= 3) {
		struct file * read_file = find_file_by_fd(fd);
		if (read_file != NULL) {
			lock_acquire(&filesys_lock);
			actually_read_byte = file_read(read_file, buffer, size);
			lock_release(&filesys_lock);
			return actually_read_byte;
		} else
			exit(-1);
	} else {
		exit(-1);
	}
}

int 
write (int fd, const void *buffer, unsigned size) {
	if (fd == 1) {
			lock_acquire(&filesys_lock);
			putbuf(buffer, size);
			lock_release(&filesys_lock);
			return size;
	} else if (fd >= 3) {
		struct file * write_file = find_file_by_fd(fd);
		if (write_file != NULL) {
			int actually_write_byte;
			lock_acquire(&filesys_lock);
			actually_write_byte = file_write(write_file, buffer, size);
			lock_release(&filesys_lock);
			return actually_write_byte;
		} else {  // can't find open file "fd"
			exit(-1);
		}
	} else {
		exit(-1);
	}
	NOT_REACHED();
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
		// 얘 때문에 위에 e 선언 for-loop 안으로 제한하면 안됨
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

// "fd"에 해당하는 open file이 있을 경우 해당 file pointer를 리턴
// 찾지 못했을 경우 NULL을 리턴
static struct file *
find_file_by_fd (int fd) {
	for (struct list_elem * e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e)) {
		struct fd_elem * tmp_fd = list_entry(e, struct fd_elem, elem);
		if (fd == tmp_fd->fd) { 
			return tmp_fd->file_ptr;
		}
	}
	return NULL;

}