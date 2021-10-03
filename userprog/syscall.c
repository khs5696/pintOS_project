#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

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


// HS
static struct lock filesys_lock;

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
	
	// HS
	lock_init(&filesys_lock);
}


// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if ((uint64_t)addr >= 0x8004000000) {
		exit(-1);
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// HS 2-2-1. syscall_handler 구현
	memcpy(thread_current()->tf, f, sizeof(struct intr_frame));

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
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			check_address(f->R.rdi);
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			check_address(f->R.rdi);
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			check_address(f->R.rdi);
			f->R.rax = remove(f->R.rdi);
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
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			thread_exit();
			break;
	}

	printf("system call\n");
	thread_exit();
}

/* System Call 함수 구현 */
// pintOS를 종료시킨다.
void halt(void) {
	power_off();
}

void exit (int status) {
	thread_current()->exit_code = status;
	thread_exit();
}

bool create (const char *file, unsigned initial_size) {
	lock_acquire(&filesys_lock);
	bool result = filesys_create(file, initial_size);
	lock_release(&filesys_lock);
	return result;
}

bool remove (const char *file) {
	lock_acquire(&filesys_lock);
	bool result = filesys_remove(file);
	lock_release(&filesys_lock);
	return result;
}

int open (const char *file) {
	
}