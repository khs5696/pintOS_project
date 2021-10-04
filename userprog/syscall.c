#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "include/filesys/file.h"
#include "include/threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
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

	lock_init(&file_lock);
}


// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if ((uint64_t)addr >= 0x8004000000) {
		exit(-1);
	}
	// printf("address is valid\n");
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// printf("system call\n");

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
			printf("close\n");
			break;
		default:
			thread_exit();
			break;
	}
}

void halt(void) {
    power_off();
	NOT_REACHED();
}

void exit (int status) {
	thread_current()->exit_status = status;
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size){
	bool result;

    if (file == NULL){ exit(-1); }

	lock_acquire(&file_lock);
	result = filesys_create(file, initial_size);
	lock_release(&file_lock);

	return result;
}

int open (const char *file) {   
    int open_fd;
	// file(argument)이 null이 아닌지를 확인
    if (file == NULL) { exit(-1); }

	// filesys_open() 함수를 이용하여 파일을 오픈 상태로 변경한다.
    lock_acquire(&file_lock);
    struct file * new_open_file = filesys_open(file);	
    if (new_open_file != NULL) {
		// file descriptor(fd)를 할당받아 file_structure 구조체를 생성하고
		// thread_current()의 thread_file_list에 삽입하고 fd를 반환한다.
		struct file_structure * tmp;
		tmp->file = file;
		tmp->file_descriptor = thread_current()->fd;
		list_push_back(&thread_current()->thread_file_list, &tmp->file_elem);
		open_fd = thread_current()->fd;
		thread_current()->fd++;
    } else {
		open_fd = -1;
    }
    lock_release(&file_lock);

    return open_fd;
}

// HS 2-2-2. write 시스템 콜 구현
// 작성한 바이트 수를 반환한다. (전부 작성하지 못한 경우, size보다 작을 수 있음)
int write(int fd, const void *buffer, unsigned size) {
    int result = 0;

	// Synchronization 고려
    // lock_acquire(&file_lock);

	// fd가 STDOUT(1)인 경우, console에 putbuf()를 호출하여 작성한다.
    if (fd == 1) {
		lock_acquire(&file_lock);
        putbuf(buffer, size);
        result = size;
    } 
	// fd가 STDOUT이 아닌 경우,
	else {
		struct thread * cur = thread_current();
		struct file_structure * tmp;
		// thread_current()의 thread_file_list에서 fd에 해당하는 파일을 찾고
		for (struct list_elem * element = list_begin(&cur->thread_file_list); element != list_end(&cur->thread_file_list); element = list_next(element) ) {
			tmp = list_entry(element, struct file_structure, file_elem);
			if (tmp->file_descriptor == fd) { break; }
			tmp = NULL;
		}

        if (tmp != NULL) {
			// file_write() 함수를 호출하여 file에 작성한다.
			lock_acquire(&file_lock);
    		result = file_write(tmp->file, buffer, size);
        } else {
    		result = -1;
        }
    }

    lock_release(&file_lock);

    return result;
}
