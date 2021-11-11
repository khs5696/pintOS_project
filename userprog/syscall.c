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
#include "userprog/process.h"
#include "threads/palloc.h"

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

	// HS 2-2-0. System call 구현을 위한 변수 초기화
	lock_init(&file_synch_lock);
	current_fd_num = 3;
}

// HS 2-2-1. check_address 함수 구현
// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// JH 또 user가 전달한 pointer가 mapping 되지 않았을 수도 있음으로 이것도 체크
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	// if (!is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4, addr))	{
	if (!is_user_vaddr(addr)) {
		exit(-1);
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// HS 2-2-2. syscall_handler 구현
	memcpy(&thread_current()->fork_intr, f, sizeof(struct intr_frame));

	// 인터럽트 f에서 레지스터에 대한 정보 R을 가져오고, 
	// 시스템 콜 넘버(f->R.rax)에 해당하는 시스템 콜을 switch문으로 호출
	// 포인터 argument가 필요한 시스템 콜의 경우, 유저 메모리 영역(0~KERN_BASE)에 해당하는지를 확인
	// 시스템 콜 함수의 반환 값은 f->R.rax에 저장
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
		case SYS_MMAP:
			f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
			break;
		case SYS_MUNMAP:
			// check_address(f->R.rdi);
			munmap(f->R.rdi);
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

// HS 2-7-0. exit() system call
void
exit (int status) {
	thread_current()->exit_status = status;
	// HS 2-3-1. Process Termination Message 출력
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

pid_t
fork (const char *thread_name) {
	// HS 2-5-1. fork() system call : process_fork()로 새로운 child 스레드 생성
    pid_t child_pid = (pid_t) process_fork(thread_name, &thread_current()->fork_intr);

    if (child_pid == TID_ERROR)			// fork로 새로운 프로세스를 만드는 것에 실패
    	return TID_ERROR;		
    else {
    	struct thread * child_thread = NULL;
		struct list_elem * index_elem;

		for (index_elem = list_begin(&thread_current()->child_thread_list); index_elem != list_end(&thread_current()->child_thread_list); 
		 index_elem = list_next(index_elem)) {
			struct thread * tmp = list_entry(index_elem, struct thread, child_elem);
			if (tmp->tid == child_pid) {
				child_thread = tmp;
				break;
			}
		}
		if (child_thread == NULL) {		// 만들기는 만들었는데, child_thread_list에서 찾아보니까 없는 경우 -> process_fork가 이상함....
			return TID_ERROR;
		} else {
			// HS 2-5-3. __do_fork()가 실행될 때까지 대기하기 위해 do_fork_sema를 sema_down()
			// __do_fork()를 실행할 프로세스를 새로 만들었지만, 아직 함수가 실행 되지 않았음으로
			// __do_fork()를 실행시켜 부모 프로세스를 완전히 복제할 수 있도록 기다려주는 역할
			sema_down(&child_thread->do_fork_sema);

			// 자식 프로세스가 'sema_down(&parent->do_fork_sema);'를 실행시킴으로써 user program을 실행시키기 전
			// 부모에게 주도권을 한번 넘겨준 상황 -> 만약 child_thread가 __do_fork 중 비정상적으로 끝났다면,
			// 바로 return TID_ERROR
			if (child_thread->exit_status == -1) {
				return TID_ERROR;
			}
			// HS 2-5-6. 다시 sema_up을 통해 자식이 이후에 정상적으로 do_iret을 할 수 있도록 해주는 역할
			sema_up(&thread_current()->do_fork_sema);
		}
    	return child_pid;
	}
	NOT_REACHED(); 
}

int
exec (const char * cmd_line) {
	char * cmd_line_copy = (char *) malloc(strlen(cmd_line)+1);
	strlcpy(cmd_line_copy, cmd_line, strlen(cmd_line)+1);

	int exec_result = process_exec(cmd_line_copy);
	thread_current()->exit_status = exec_result;

	return exec_result;
}

// HS 2-7-0. wait() system call
int wait(tid_t child_tid) {
    return process_wait(child_tid);
}

bool
create(const char *file, unsigned initial_size) {
	bool create_result;

	if (file == NULL) { exit(-1); }		// file name error

	// filesys_create()로 파일을 생성하는 동안, synchronization을 통해 추가적인 접근을 제한한다.
	lock_acquire(&file_synch_lock);
	create_result = filesys_create(file, initial_size);
	lock_release(&file_synch_lock);

	return create_result;
}

bool
remove (const char * file) {
	bool remove_result;

	if (file == NULL){ exit(-1); }		// file name error

	// filesys_remove()로 파일을 제거하는 동안, synchronization을 통해 추가적인 접근을 제한한다.
	lock_acquire(&file_synch_lock);
	remove_result = filesys_remove(file);
	lock_release(&file_synch_lock);

	return remove_result;
}

int
open(const char * file) {
	if (file == NULL) { return -1; }	// file name error
	
	// filesys_open()으로 파일을 여는 동안, synchronization을 통해 추가적인 접근을 제한한다.
	lock_acquire(&file_synch_lock);
	struct file * open_file = filesys_open(file);
	lock_release(&file_synch_lock);

	if (open_file == NULL) { 			// file open error
		return -1;
	} else if (list_size(thread_current()->fd_list) > 130) {
		lock_acquire(&file_synch_lock);		// Too much file error
		file_close(open_file);
		lock_release(&file_synch_lock);
		return -1;
	} else { 							// file open complete!
		/* fd_list에 추가하기 위해 fd_elem 구조체 생성 */
		struct fd_elem * new_fd_elem = malloc(sizeof(struct fd_elem));
		
		// fd를 정하는 과정. 일단은 fd 계속 증가
		new_fd_elem->fd = current_fd_num;
		new_fd_elem->file_ptr = open_file;
		current_fd_num++;
		
		// HS 2-4-1. Deny Write on Executables
		// 실행 중인 유저 프로그램에 대한 변경을 막기 위해 file_deny_write() 사용
		// 접근 제한은 file_close()의 file_allow_write()에 의해서 프로그램이 종료 될 때 해제
		if (!strcmp(thread_current()->name, file))
			// void file_deny_write (struct file *) 메모리에 프로그램 적재 시(load), 프로그램 파일에 쓰기 권한 제거
			file_deny_write(open_file);
	
		list_insert_ordered(thread_current()->fd_list, &new_fd_elem->elem, compare_by_fd, NULL);

		return new_fd_elem->fd;
	}
}

int
filesize (int fd) {
	struct file * size_check_file_ptr = find_file_by_fd(fd);

	if (size_check_file_ptr != NULL)
		return file_length(size_check_file_ptr);
	else
		exit(-1);
}

int
read (int fd, const void *buffer, unsigned size) {
	int actually_read_byte = 0;

	// 파일을 읽는 동안, synchronization을 통해 추가적인 접근을 제한한다.	
	if (fd == 0) { 	// STDIN	
		lock_acquire(&file_synch_lock);
		actually_read_byte = input_getc();
		lock_release(&file_synch_lock);

		return actually_read_byte;
	} else if (fd >= 3) {
		struct file * read_file = find_file_by_fd(fd);
		
		if(spt_find_page(&thread_current()->spt, buffer) != NULL && spt_find_page(&thread_current()->spt, buffer)->writable == 0)
			exit(-1);

		if (read_file != NULL) {
			lock_acquire(&file_synch_lock);
			actually_read_byte = file_read(read_file, buffer, size);
			lock_release(&file_synch_lock);
			return actually_read_byte;
		} else {
			exit(-1);
		}
	} else {
		exit(-1);
	}
}

int 
write (int fd, const void *buffer, unsigned size) {
	// 파일을 변경하는 동안, synchronization을 통해 추가적인 접근을 제한한다.
	if (fd == 1) {					// STDOUT
		lock_acquire(&file_synch_lock);
		putbuf(buffer, size);
		lock_release(&file_synch_lock);

		return size;
	} else if (fd >= 3) {
		struct file * write_file = find_file_by_fd(fd);
		if (write_file != NULL) {
			int actually_write_byte;

			lock_acquire(&file_synch_lock);
			actually_write_byte = file_write(write_file, buffer, size);
			lock_release(&file_synch_lock);

			return actually_write_byte;
		} else { exit(-1); }		 // can't find open file "fd"
	} else { exit(-1); }
	NOT_REACHED();
}

void seek (int fd, unsigned position) {
	// file_seek()를 이용하여 current position을 new_pos로 변경
	// void file_seek (struct file *file, off_t new_pos)
	file_seek(find_file_by_fd(fd), position);
}

unsigned tell (int fd) {
	// file_tell()를 이용하여 fd에 해당하는 파일의 current position을 반환
	// off_t file_tell (struct file *file)
	return (unsigned) file_tell(find_file_by_fd(fd));
}

// JH fd가 너무 많아서 구별해주려고 parameter이름 arg_fd로 한거임....
// 좋은 이름 추천 받아요
void
close (int arg_fd) {
	struct list_elem * index_elem;
	struct fd_elem * close_fd = NULL;
	bool find_fd_success = false;

	// 실행 중인 스레드의 fd_list를 순회하며 arg_fd에 해당하는 closing할 파일을 탐색
	for (index_elem = list_begin(thread_current()->fd_list); index_elem != list_end(thread_current()->fd_list); 
			index_elem = list_next(index_elem)) {
		struct fd_elem * tmp_fd = list_entry(index_elem, struct fd_elem, elem);
		if (arg_fd == tmp_fd->fd) {
			find_fd_success = true;
			close_fd = tmp_fd;
			break;
		}
	}
	if (find_fd_success == true) {
		// fd_list에서 close 하고자 하는 fd_elem 제거
		// 얘 때문에 위에 e 선언 for-loop 안으로 제한하면 안됨
		list_remove(index_elem);

		// 해당 fd에 연결되어 있는 open file close
		// 파일을 닫는 동안, synchronization을 통해 추가적인 접근을 제한한다.
		lock_acquire(&file_synch_lock);
		file_close(close_fd->file_ptr);
		lock_release(&file_synch_lock);

		// malloc()으로 만들어줬던 fd_elem free
		free(close_fd);
	} else {
		exit(-1);
	}
}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
	// JH 3-4-1 system call mmap 구현
	// offset에서 시작해서 fd로 open된 file의 length byte만큼을 process의 virtual address space addr에 연속적으로 mapping
	// 성공 : file이 mapping 되기 시작한 addr를 리턴
	// fd로 열린 파일의 길이가 0인 경우 실패 -> NULL 리턴 (v)
	// addr이 page-aligned가 아닌 경우 실패 -> NULL 리턴 (v)
	// mapping의 범위가 이미 존재하고 있던 page를 덮어버리려고 하는 경우 실패 -> NULL 리턴 (do_mmap에서 함)
	// addr가 0이면 실패 -> NULL 리턴 (v)
	// length가 0이면 실패 -> NULL 리턴 (v)
	// stdin, stdout을 mapping하는 것 금지 (v)
	// void * do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset);

	// find_file_by_fd로 fd_list에서 fd 찾기 -> 없으면 NULL (v)
	// file_reopen을 해주는데 fd로 찾아지면 그걸 굳이 또 reopen을 해야하나...? 라는 생각
	// file_size가 offset보다 작은 경우 false (v)
	if (is_kernel_vaddr(addr))
		return NULL;
	if (addr == NULL || length <= 0 || fd < 2)	// addr가 NULL이거나 length가 0보다 작거나 STDIN&OUT을 mapping 하려고 하면 return NULL
		return NULL;
	if (length >= KERN_BASE)	// mmap-kernel case 해결
		return NULL;
	if (pg_round_down(addr) != addr)	// addr가 page-aligned되어 들어오지 않은 경우 return NULL
		return NULL;
	if (pg_round_down(offset) != offset)
		return NULL;

	struct file * file = find_file_by_fd(fd);
	if (!file)	// fd_list에서 file 찾았는데 없으면 NULL 리턴
		return NULL;
	off_t file_size = file_length(file);
	if(file_size == 0 || file_size <= offset)	// open된 file의 길이가 0이거나 file의 길이보다 offset이 더 큰 경우 NULL 리턴
		return NULL;
	
	void * page_addr = addr;
	
	return do_mmap(addr, length, writable, file, offset);
}

void
munmap (void *addr) {
	// addr이 page-aligned가 아닌 경우 return
	if (pg_round_down(addr) != addr)
    	return;
	struct page * p = spt_find_page(&thread_current()->spt, addr);
	if (p == NULL)	// spt에서 찾았는데 없는 경우 -> 잘못된 addr 주소
		return;
	if (p->operations->type != VM_FILE || !p->file.is_first)	// page의 type이 VM_FILE이 아니거나, 해당 페이지가 처음 페이지가 아닌 경우
		return;


	// printf("I'm doing do_munmap\n");
  	do_munmap(addr);

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
	struct list_elem * index_elem;

	for (index_elem = list_begin(thread_current()->fd_list); index_elem != list_end(thread_current()->fd_list); 
		index_elem = list_next(index_elem)) {
		struct fd_elem * tmp_fd = list_entry(index_elem, struct fd_elem, elem);
		
		if (fd == tmp_fd->fd) { 
			return tmp_fd->file_ptr;
		}
	}
	return NULL;

}
