#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif
#ifdef EFILESYS
#include "filesys/directory.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
// 수정
 struct file *exec_file;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */

	// HS 1-1-0. 스레드가 일어나야할 시간(tick)에 대한 정보
	int64_t ticks_to_wake;

	// HS 1-5-0. Donation을 위한 변수
	int origin_priority;				// 스레드의 기존 우선순위
	struct lock * waiting_lock;			// 스레드가 기다리고 있는 lock
	struct list donated;				// 스레드에게 우선순위를 양보한 스레드의 리스트
	struct list_elem donated_elem;

	// HS 1-6-0. Advanced scheduler을 위한 변수
	int nice;
	int recent_cpu;

	// HS 2-0-0. project2를 위한 변수
	int exit_status;						// process_exit() & wait()를 위한 변수

	struct list * fd_list;					// 현재 프로세스가 가지고 있는 fd_elem의 list
	struct list child_thread_list;			// 현재 프로세스가 fork한 children의 list
	struct list_elem child_elem;

	struct semaphore waiting_child_sema;	// process_wait() - child의 exit을 확인하기 위해 (2-7)
	struct semaphore do_fork_sema;			// fork() - child에서 do_fork의 완료를 확인하기 위해
	struct semaphore exit_child_sema;		// process_exit() - child에서 exit_status의 전달 완료를 확인하기 위해 (2-7)
	struct semaphore waiting_load_sema;		// create_initd() - child의 load() 완료를 확인하기 위해 (2-6)

	struct thread * parent_thread;			// 현재 프로세스의 부모 스레드
	struct intr_frame fork_intr;			// fork()를 위한 interrupt 변수

	/* 한양대 : thread(=process)마다 현재 작업중인 directory를 기억하기 위해 struct dir 포함 필요 */
#ifdef EFILESYS
	struct dir * work_dir;
#endif
	/* data */

	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;
 
void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

// HS 1-1
void thread_sleep(int64_t ticks);
void thread_awake(int64_t ticks);

// HS 1-2
bool compare_by_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void thread_set_priority_update(void);

// HS 1-5
bool compare_donate_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void donation(void);
void donated_update(struct lock * lock);
void reset_donation(void);

// HS 1-6
void calculate_priority(struct thread * t);
void calculate_recent_cpu(struct thread * t);
void calculate_load_avg (void);

void update_recent_cpu (void);
void recalculate_priority (void);
void recalculate_recent_cpu (void);
#endif /* threads/thread.h */