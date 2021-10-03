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

	lock_init(&filesys_lock);
}


// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if ((uint64_t)addr >= 0x8004000000) {
		printf("address is not valid\n");
	}
	printf("address is valid\n");
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	printf("system call\n");

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
			printf("exit\n");
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
			printf("create\n");
			break;
		case SYS_REMOVE:
			printf("remove\n");
			break;
		case SYS_OPEN:
			printf("open\n");
			break;
		case SYS_FILESIZE:
			printf("filesize\n");
			break;
		case SYS_READ:
			printf("read\n");
			break;
		case SYS_WRITE:
			printf("write\n");
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

void exit (int status) {
	thread_current()->exit_status = status;
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

int write(int fd, const void *buffer, unsigned size)
{
    int write_result = 0;
    lock_acquire(&filesys_lock);
    if (fd == 1) {
		printf("fd writing\n");
        putbuf(buffer, size);
		printf("buffer is printed\n");
        write_result = size;
    }
    else {
		printf("not fd writing\n");
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
