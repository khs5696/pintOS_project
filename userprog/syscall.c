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

	lock_init(&filesys_lock);
	fd_cnt = 3;
}


// argument로 주어진 포인터가 유저 메모리 영역(0 ~ KERN_BASE)인지 확인
// JH 또 user가 전달한 pointer가 mapping 되지 않았을 수도 있음으로 이것도 체크
// 잘못된 포인터를 제공할 경우, 사용자 프로세스 종료
void check_address (void * addr) {
	if (!is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4, addr))	{
		// printf("not valid address\n");
		exit(-1);
	}
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// HS 2-2-1. syscall_handler 구현
	memcpy(&thread_current()->fork_tf, f, sizeof(struct intr_frame));

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

pid_t
fork (const char *thread_name) {;
    pid_t child_pid = (pid_t) process_fork(thread_name, &thread_current()->fork_tf);
    if (child_pid == TID_ERROR)
    	return TID_ERROR;
    else {
    	struct thread * child = NULL;

    	for (struct list_elem * e = list_begin(&thread_current()->child_list); e != list_end(&thread_current()->child_list); e = list_next(e)) {
        	child = list_entry(e, struct thread, child_elem);
        	if (child->tid == child_pid) {
        		sema_down(&child->load_sema);
				//여기서 만약 exit_status가 -1이면 바로 그냥 return TID_ERROR;
				sema_up(&thread_current()->load_sema);
            break;
         }
      }
      return child_pid;
   }
   NOT_REACHED(); 
}

int
exec (const char * cmd_line) {
   char * cmd_copy = (char *) malloc(strlen(cmd_line)+1);
   strlcpy(cmd_copy, cmd_line, strlen(cmd_line)+1);
   int result = process_exec(cmd_copy);
   thread_current()->exit_status = result;
   return result;
}

int wait(tid_t child_tid) {
    /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
    * XXX:       to add infinite loop here before
    * XXX:       implementing the process_wait. */
    return process_wait(child_tid);
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

bool
remove (const char * file) {
   bool result;

  if (file == NULL){
         exit(-1);
  }
   lock_acquire(&filesys_lock);
   result = filesys_remove(file);
   lock_release(&filesys_lock);

   return result;
}

int
open(const char * file) {
	if (file == NULL)				// file name error
		return -1;
	
	// filesys_open()으로 파일을 여는 동안, synchronization을 통해 추가적인 접근을 제한한다.
	lock_acquire(&filesys_lock);
	struct file * open_file = filesys_open(file);
	lock_release(&filesys_lock);

	if (open_file == NULL) { 		// file open error
		// printf("open fail : open file is NULL\n");
		return -1;
	} else if(list_size(thread_current()->fd_list) > 130) {
		lock_acquire(&filesys_lock);
		file_close(open_file);
		lock_release(&filesys_lock);
		return -1;
	} else { 						// file open complete!
		/* fd_list에 추가하기 위해 fd_elem 구조체 생성*/
		struct fd_elem * new_fd = malloc(sizeof(struct fd_elem));
		
		// fd를 정하는 과정 - 일단은 fd 계속 증가
		new_fd->fd = fd_cnt;
		new_fd->file_ptr = open_file;
		fd_cnt++;
		
		// HS 2-4-1. Deny Write on Executables
		// 실행 중인 유저 프로그램에 대한 변경을 막기 위해 file_deny_write() 사용
		// 접근 제한은 file_close()의 file_allow_write()에 의해서 프로그램이 종료 될 때 해제
		if (!strcmp(thread_current()->name, file))
			// void file_deny_write (struct file *) 메모리에 프로그램 적재 시(load), 프로그램 파일에 쓰기 권한 제거
			file_deny_write(open_file);
	
		list_insert_ordered(thread_current()->fd_list, &new_fd->elem, compare_by_fd, NULL);

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
	
	if (fd == 0) { 	// STDIN	
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
	struct thread * curr = thread_current();
	struct list_elem * e;
	struct fd_elem * close_fd = NULL;
	bool find_fd = false;
	for (e = list_begin(curr->fd_list); e != list_end(curr->fd_list); e = list_next(e)) {
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
	for (struct list_elem * e = list_begin(thread_current()->fd_list); e != list_end(thread_current()->fd_list); e = list_next(e)) {
		struct fd_elem * tmp_fd = list_entry(e, struct fd_elem, elem);
		if (fd == tmp_fd->fd) { 
			return tmp_fd->file_ptr;
		}
	}
	return NULL;

}