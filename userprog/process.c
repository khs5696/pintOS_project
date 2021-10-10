#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/syscall.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	
	// HS 2-1-3. filename 토큰화 관련 변수 선언
	char * command_name;
	char * child_thread_name;
	char * parsing_ptr;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, strlen(file_name)+1);

	// HS 2-1-3. filename 토큰화
	command_name = palloc_get_page (0);
	if (command_name == NULL)
		return TID_ERROR;
	strlcpy (command_name, file_name, strlen(file_name)+1);
	child_thread_name = strtok_r(command_name, " ", &parsing_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (child_thread_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR) {
		palloc_free_page (fn_copy);
		palloc_free_page (command_name);	// 할당된 메모리 해제
		return TID_ERROR;
	}

	// HS 2-6-1. 생성된 자식 스레드에서 load()를 실행하는 동안 종료되는 경우를 방지
	sema_down(&thread_current()->waiting_load_sema);

	// exit(-1)로 종료된 자식 스레드가 있는 경우 대기
	struct list_elem * index_elem;
	for (index_elem = list_begin(&thread_current()->child_thread_list); index_elem != list_end(&thread_current()->child_thread_list);
	 index_elem = list_next(index_elem)) {
		struct thread * exit_child_thread = list_entry(index_elem, struct thread, child_elem);
		if (exit_child_thread->exit_status == -1) {
			return process_wait(tid);
		}
	}

	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
   /* Clone current thread to new thread.*/
   tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, thread_current());
   
	// JH 스레드를 만들기만 하고 다시 돌아옴 thread_create 안에 init_thread에서
	// 현재 스레드의 child_thread_list에 새로 생성하는 thread를 넣는 작업이 있기 때문에
	// 이게 이루어 지지 않았다면, 현재 스레드의 child_thread_list가 비어있을 것임!
	if (!list_empty(&thread_current()->child_thread_list)) {
		return tid;
	} else {
		return TID_ERROR;
	}
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* duplicate_pte 구현 - do_fork()에서 page를 복사하기 위해 */
	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	// 커널 영역을 가리키는 경우, 추가적인 작업 없이 return
	if (is_kernel_vaddr(va)) { return true; }

	/* 2. Resolve VA from the parent's page map level 4. */
	// 부모 스레드의 pml4에서 va에 해당하는 영역(페이지)를 불러온다.
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	// 자식 스레드에 pml4를 복사하기 위해 새로운 페이지 할당
	newpage = palloc_get_page(PAL_USER);
	if (!newpage)
		return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	// 부모 스레드의 pml4에서 불러온 pte를 자식 스레드에게 복사
	memcpy(newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page(newpage);
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* HS. do_fork 구현 */
	// 부모의 인터럽트를 그대로 전달할 경우 변경될 수 있기에, 복사하여 전달
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &parent->fork_intr;
	bool succ = true;
	
	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);

#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) {
		goto error;
	}
#endif
   /* TODO: Your code goes here.
    * TODO: Hint) To duplicate the file object, use `file_duplicate`
    * TODO:       in include/filesys/file.h. Note that parent should not return
    * TODO:       from the fork() until this function successfully duplicates
    * TODO:       the resources of parent.*/
   // HS. 부모 스레드에 저장되어 있는 파일들을 자식 스레드로 복사한다. (file_duplicate() 이용)
	for (struct list_elem * index_elem = list_begin(parent->fd_list); index_elem != list_end(parent->fd_list); 
	 index_elem = list_next(index_elem)) {
		struct fd_elem * file_element = list_entry(index_elem, struct fd_elem, elem);
		struct file * new_file_element = file_duplicate(file_element->file_ptr);

		if (new_file_element == NULL)		// file_duplicate error
			goto error;
		
		// 자식 스레드의 fd_list에 추가하기 위해 fd_elem 구조체 선언 및 변수 할당
		struct fd_elem * new_elem = (struct fd_elem *) malloc(sizeof(struct fd_elem));

		if (new_elem == NULL)
			goto error;
		
		new_elem->file_ptr = new_file_element;
		new_elem->fd = file_element->fd;
		list_push_back(current->fd_list, &new_elem->elem);
	}

   	process_init ();
	// 부모 프로세스를 제대로 복제하였음으로, 자신을 그만 기다려도 된다고 신호를 주는 역할

   	sema_up(&current->do_fork_sema);
	// JH : fork의 제대로된 역할은 부모 프로세스를 그대로 복제하는 자식 프로세스를 만드는 것에서 그쳐야 한다고 생각
	// 따라서 아래의 do_iret이 실행되면 복제하는 것도 모자라 바로 실행까지 시켜버림으로 그것을 방지하고 복제까지만
	// 하도록 하기 위한 역할
	sema_down(&parent->do_fork_sema);

	/* Finally, switch to the newly created process. */
	if (succ){
		if_.R.rax = 0;
		do_iret (&if_);
	}
      
error:
	sema_up(&current->do_fork_sema);
	// fork부터 do_fork 과정 도중에 실패했을 경우, 프로세스를 복제하는데 실패했음을 표시하고
	// 부모가 이 사실을 알 수 있도록 기다린 후 종료한다.
	thread_current()->exit_status = -1;
	sema_down(&parent->do_fork_sema);
	
   	thread_exit ();
}


int
process_exec(void *f_name) {
	char *file_name = f_name;
	bool success;

	/* HS 2-1-0. Command Line Parsing을 위한 변수 선언 */
	// Command Parsing 관련 변수
 	char *parsing_token;
	char *next_token;

	// Stack Organization 관련 변수
	int argc = 0; 
	int command_len = 0;			// alignment를 위해 token들이 stack에서 차지하는 byte
	char *argv[50];	
	char *command_address[50];		// stack에서의 각 token 주소(포인터)를 저장할 배열

	/* HS 2-1-1. Command Parsing */
	// f_name을 parsing하여 토큰화시키고 argv[argc]에 순서대로 저장
	/*Warning: cannot use f_name anymore since strtok_r is used to f_name*/
	parsing_token = strtok_r(f_name, " ", &next_token);
	argv[argc] = parsing_token;

	while (parsing_token) {
		argc = argc + 1;
		parsing_token = strtok_r(NULL, " ", &next_token);
		argv[argc] = parsing_token;
	}

	/* We cannot use the intr_frame in the thread structure.
	* This is because when current thread rescheduled,
	* it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup();
	/* And then load the binary */
	success = load(argv[0], &_if);
	/* If load failed, quit. */

	// HS 2-6-2. 자식 스레드가 load() 하는 동안 부모 스레드(initd)가 종료되는 경우를 방지하기 위해
	// create_initd()에서 대기 중인 waiting_load_sema를 sema_up
	sema_up(&thread_current()->parent_thread->waiting_load_sema);

	if (!success)
		return -1;
	
	/* HS 2-1-2. Stack Organization */
	// argv에 저장된 token을 순서대로 stack에 삽입
	int length = 0;
	for (int i = argc - 1; i > -1; i--) {
		length = strlen(argv[i]) + 1;				// '\0'도 포함 
		command_len += length;						// alignment를 위해 command_len 업데이트
		_if.rsp = (char *)_if.rsp - length;			// token의 크기만큼 rsp(stack pointer) 이동
		memcpy (_if.rsp, argv[i], length);			// rsp에 token을 복사
		command_address[i] = (char *) _if.rsp;		// 각 token의 주소를 배열에 저장
	}
	// Alignment를 위해 padding 영역만큼 rsp 이동
	if ((command_len % sizeof(uintptr_t)) != 0) {	
		int align_padding = sizeof(uintptr_t) - (command_len % sizeof(uintptr_t));
		_if.rsp = (char *)_if.rsp - align_padding;
	}

	// 0을 stack에 삽입 & token의 주소들을 순서대로 stack에 삽입
	_if.rsp = (char *)_if.rsp - sizeof(char *);
	*(uint64_t *) _if.rsp = 0;
	for (int i = argc - 1; i > -1; i--) {
		_if.rsp = (char *)_if.rsp - sizeof(char *);
		*(uint64_t *) _if.rsp = command_address[i];
	}

	// return address 삽입
	_if.rsp = (char *)_if.rsp - sizeof(uintptr_t *);
	*(uint64_t *)_if.rsp = 0;

	_if.R.rdi = argc;
	_if.R.rsi = (uintptr_t *)_if.rsp + 1;

	// hex_dump(_if.rsp, _if.rsp, USER_STACK - _if.rsp, true);

	/* Start switched process. */
	do_iret(&_if);
	palloc_free_page(file_name); 
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* process_wait 구현 */
	int result;
	struct list_elem * index_elem;
	struct thread * child_thread = NULL;

	// HS 2-7-1. child_tid(argument)에 해당하는 자식 스레드를 child_thread_list에서 탐색
	for (index_elem = list_begin(&thread_current()->child_thread_list); index_elem != list_end(&thread_current()->child_thread_list);
	 index_elem = list_next(index_elem)) {
		child_thread = list_entry(index_elem, struct thread, child_elem);
		if (child_thread->tid == child_tid) {
			// child_thread가 종료되기 전까지는 실행 중인 스레드가 종료되면 안되므로 sema_down()
			sema_down(&child_thread->waiting_child_sema);
			
			// HS 2-7-3. child_thread가 종료되면, exit_status를 받아오고 child_thread_list에서 제거
			// child_thread_list에서 제거되었음을 child_thread에게 sema_up()으로 알려준다.
			result = child_thread->exit_status;
			list_remove(index_elem);
			sema_up(&child_thread->exit_child_sema);
			
			return result;
		}
	}
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();

	// HS 2-7-2. process_exit 구현
	/* 공식 문서 System Calls의 'close' 함수 설명
	 * process가 exit할 때 해당 process가 open한 file 전부 닫아줘야함 */
	while (!list_empty(curr->fd_list)) {
		struct fd_elem * tmp = list_entry(list_pop_front(curr->fd_list), struct fd_elem, elem);

		// 파일을 닫는 동안, 추가적인 접근을 통제하기 위해 synchronization
		lock_acquire(&file_synch_lock);
		file_close(tmp->file_ptr);
		lock_release(&file_synch_lock);
		free(tmp);
	}

	free(curr->fd_list);

	// child_thread_list의 자식 스레드들과의 연결을 끊어준다. Orphan
	while (!list_empty(&curr->child_thread_list)) {
		struct thread * tmp = list_entry(list_pop_front(&curr->child_thread_list), struct thread, child_elem);
		if (tmp->parent_thread == curr) {
				tmp->parent_thread = NULL;
		}
	}

	// 자식 스레드보다 wait 중인 부모가 먼저 종료되는 것을 방지하기 위해
	// sema_down()되어 있는 waiting_child_sema를 sema_up
	sema_up(&curr->waiting_child_sema);

	// process_wait()에서 부모 스레드에게 exit_status를 전달하기 전까지는
	// 자식 스레드의 메모리가 삭제되지 않아야하므로 sema_down()
	sema_down(&curr->exit_child_sema);

	// 스레드의 리소스 정리
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	// HS 2-4-1. Deny Write on Executables
	// 실행 중인 유저 프로그램에 대한 변경을 막기 위해 file_deny_write() 사용
	// 접근 제한은 file_close()의 file_allow_write()에 의해서 프로그램이 종료 될 때 해제
	// void file_deny_write (struct file *) 메모리에 프로그램 적재 시(load), 프로그램 파일에 쓰기 권한 제거
	file_deny_write(file);

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */