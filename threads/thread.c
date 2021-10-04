#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed_point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

// HS 1-1-0. sleep 상태(block)의 스레드들이 저장되는 리스트
static struct list sleep_list;


/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

// HS 1-1-0. 두 스레드의 일어나야할 시간을 비교하는 함수 선언
static bool compare_by_wake_ticks (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

// HS 1-6-0. Advanced scheduler을 위한 변수 선언
int load_avg;

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();

	// HS 1-1-0. 잠자는 스레드들의 목록 초기화
	list_init(&sleep_list);

}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	// HS 1-6-0. Advanced scheduler을 위한 변수 초기화
	load_avg = 0;

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

#ifdef USERPROG
	t->parent_thread = thread_current();
	list_push_back(&thread_current()->child_list, &t->child_elem);
#endif

	/* Add to run queue. */
	thread_unblock (t);

	// HS 1-2-4. 생성된 스레드의 우선순위가 현재 실행 중인 스레드보다 높을 경우,
	// 실행 중인 스레드는 CPU를 양보하고 ready_list로 들어간다.
	if (priority > thread_current()->priority) {
		thread_yield();
	}

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);

	// HS 1-2-1. unblock되는 스레드가 ready_list에 들어갈 때 우선순위에 따라 삽입
	// void list_insert_ordered (struct list *, struct list_elem *, list_less_func *, void *aux);
	list_insert_ordered(&ready_list, &t->elem, compare_by_priority, NULL);

	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();
	if (t == NULL) {
		printf("thread is null\n");
	}
	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();

	// HS 1-2-3. 현재 실행 중인 스레드를 ready 상태로 전환할 경우
	// 우선순위에 따라 정렬해서 ready_list에 삽입한다.
	if (curr != idle_thread) {
		list_insert_ordered (&ready_list, &curr->elem, compare_by_priority, 0);
	}
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	
	// HS 1-6-9. advanced scheduler 사용 시 우선순위 변ㅕㅇ 통제
	if (thread_mlfqs) { return; }

	thread_current ()->origin_priority = new_priority;

	// HS 1-5-5. 실행 중인 스레드의 변경된 우선순위가 양보받은 값보다 커질 경우를 고려해
	// donated의 우선순위들과 비교해 업데이트한다.
	reset_donation();

	// HS 1-2-5. 현재 실행 중인 스레드의 우선순위가 변경되는 경우,
	// ready_list의 가장 큰 우선순위와 비교하여 업데이트한다.
	thread_set_priority_update();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

// HS 1-6-10. advanced scheduler 관련 함수 변경
/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	// 실행 중인 스레드의 nice 값을 변경한다.
	// 작업 중 인터럽트는 비활성화시킨다.
	enum intr_level old_level = intr_disable();
	thread_current()->nice = nice;
	// nice가 변경되므로 우선순위도 바뀌고 ready_list에서 대기 중인
	// 스레드들의 우선순위와 비교해 업데이트한다.
	calculate_priority(thread_current());
	thread_set_priority_update();

	intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	// 인터럽트를 비활성화시킨 상태에서 현재 스레드의 nice 값을 반환한다.
	int result;

	enum intr_level old_level = intr_disable();
	result = thread_current()->nice;
	intr_set_level (old_level);
	return result;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	// 인터럽트를 비활성화시킨 상태에서 load_avg에 100을 곱해서 반환한다.
	int result;

	enum intr_level old_level = intr_disable();
	result = convert_fixed_to_int(multiple_fixed_int(load_avg, 100));
	intr_set_level (old_level);
	return result;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	// 인터럽트를 비활성화시킨 상태에서 현재 스레드의 recent_cpu에 100을 곱해서 반환한다.
	int result;

	enum intr_level old_level = intr_disable();
	result = convert_fixed_to_int(multiple_fixed_int(thread_current()->recent_cpu, 100));
	intr_set_level (old_level);
	return result;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	// HS 1-5-0. Donation을 위한 변수 초기화
	t->origin_priority = priority;				// 스레드의 기존 우선순위
	t->waiting_lock = NULL;						// 스레드가 기다리고 있는 lock
	list_init(&t->donated);						// 스레드에게 우선순위를 양보한 스레드의 리스트

	// HS 1-6-0. Advanced scheduler을 위한 변수 초기화
	t->nice = 0;
	t->recent_cpu = 0;

	list_init(&t->child_list);
	list_init(&t->thread_file_list);
	sema_init(&t->fork_sema, 0);

	t->fd = 2;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

// HS 1-1-1. 실행중인 스레드(idle_thread 제외)를 ticks까지 block 상태(sleep)로 만들어준다.
void
thread_sleep(int64_t wake_ticks) {
	struct thread *curr = thread_current ();
	// 인터럽트를 금지하고 이전 인터럽트 레벨 저장
	enum intr_level old_level;
	ASSERT (!intr_context ());
	old_level = intr_disable ();

	// 스레드 내부의 일어냐야할 시간 변수 업데이트
	// sleep_list에 먼저 일어나야하는 순서대로 스레드 삽입
	if (curr != idle_thread) {
		curr->ticks_to_wake = wake_ticks;
		list_insert_ordered(&sleep_list, &curr->elem, compare_by_wake_ticks, NULL);
		thread_block();
	}
	intr_set_level(old_level);
}

// HS 1-1-2. sleep_list의 스레드들을 순회하면서 깨운다.
void
thread_awake(int64_t ticks) {
	if( !list_empty(&sleep_list) && list_entry(list_front(&sleep_list), struct thread, elem)->ticks_to_wake <= ticks) {
		ASSERT(list_entry(list_front(&sleep_list), struct thread, elem)->ticks_to_wake >= 0);

		struct thread * wake_thread = list_entry(list_pop_front(&sleep_list), struct thread, elem);
		thread_unblock(wake_thread);
		wake_thread->ticks_to_wake = -1;
		thread_awake(ticks);
	}
	return;
}

/*list_less_func whose comparision criteria is ticks_to_wake.
	This function makes ascending order.*/
static bool
compare_by_wake_ticks (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	int64_t ticks_to_wake_a = list_entry(a, struct thread, elem)->ticks_to_wake;
	int64_t ticks_to_wake_b = list_entry(b, struct thread, elem)->ticks_to_wake;
	if(ticks_to_wake_a < ticks_to_wake_b) return true;
	else if(ticks_to_wake_a == ticks_to_wake_b) {
		if (list_entry(a, struct thread, elem)->priority > list_entry(b, struct thread, elem)->priority) return true;
		else return false;
	} else return false;
}

// HS 1-2-0. list_insert_ordered의 list_less_func 인자로 사용하기 위해, 
// 두 스레드의 우선순위를 비교하는 함수를 선언한다.
// typedef bool list_less_func (const struct list_elem *a, const struct list_elem *b, void *aux);
bool compare_by_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	int priority_a = list_entry(a, struct thread, elem)->priority;
	int priority_b = list_entry(b, struct thread, elem)->priority;
	return (priority_a > priority_b);
}

// HS 1-2-5. ready_list의 첫번째 스레드(가장 큰 우선순위)의 우선순위와
// 업데이트된 현재 스레드를 비교하여, 값이 더 클 경우 실행 중인 스레드를 변경한다.
void thread_set_priority_update(void) {
	if (!list_empty(&ready_list)) {
		int ready_priority = list_entry(list_front(&ready_list), struct thread, elem)->priority;
		if (thread_get_priority() < ready_priority) {
			thread_yield();
		}
	}
}

// HS 1-5-1. donated에 정렬해서 삽입하기 위해 인자로 사용될 함수 선언
// typedef bool list_less_func (const struct list_elem *a, const struct list_elem *b, void *aux);
bool compare_donate_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	int priority_a = list_entry(a, struct thread, donated_elem)->priority;
	int priority_b = list_entry(b, struct thread, donated_elem)->priority;
	return priority_a > priority_b;
}

// HS 1-5-2. nested donation을 고려해서 우선순위 양보
// 우선순위를 양보한 holder가 또 다른 lock을 기다리고 있는 경우를 고려
// (waiting_lock->holder == NULL)
void donation(void) {
	struct thread * tmp = thread_current();

	for (int i = 0; i < 8; i++) {	
		if (tmp->waiting_lock == NULL) 
			{ break; }
		tmp->waiting_lock->holder->priority = tmp->priority;
		tmp = tmp->waiting_lock->holder;
	}
}

// HS 1-5-3. donated에서 양보 받은 스레드를 제거해 업데이트한다.
void donated_update(struct lock * lock) {
	for (struct list_elem * elem = list_begin(&thread_current()->donated); elem != list_end(&thread_current()->donated); elem = list_next(elem)) {
		struct thread * tmp = list_entry(elem, struct thread, donated_elem);
		// release로 반환한 lock = 우선순위를 양보한 스레드의 waiting_lock
		if (lock == tmp->waiting_lock) { list_remove(&tmp->donated_elem); }
	}
}

// donated 리스트중 가장 큰 값(또는 origin_priority)으로 우선 순위를 재설정한다. multiple donation 고려
void reset_donation(void) {
	thread_current()->priority = thread_current()->origin_priority;

	if (!list_empty(&thread_current()->donated)){
		list_sort(&thread_current()->donated, compare_donate_priority, 0);
		
		int donated_max_priority = list_entry(list_front(&thread_current()->donated), struct thread, donated_elem)->priority;
		int current_priority = thread_current()->priority;

		if (donated_max_priority > current_priority) {
			thread_current()->priority = donated_max_priority;
		}
	}
}

// HS 1-6-1. 주어진 스레드의 우선순위를 계산하는 함수
// PRI_MAX - (t->recent_cpu / 4) - (t->nice * 2) {
void calculate_priority(struct thread * t) {
	if (t != idle_thread) {
		int tmp1 = divide_fixed_int(t->recent_cpu, 4);
		int tmp2 = subtract_fixed_fixed(convert_int_to_fixed(PRI_MAX), tmp1);
		int tmp3 = subtract_fixed_int(tmp2, (t->nice * 2));
		t->priority = convert_fixed_to_int (tmp3);
	}
	return;
}

// HS 1-6-2. 주어진 스레드의 recent_cpu를 계산하는 함수
// (2 * load_avg) / (2 * load_avg + 1) * t->recent_cpu + t->nice
void calculate_recent_cpu(struct thread * t) {
	if (t != idle_thread) {
		int tmp = multiple_fixed_int(load_avg, 2);
		int tmp1 = add_fixed_int(tmp, 1);
		int tmp2 = divide_fixed_fixed(tmp, tmp1);
		int tmp3 = multiple_fixed_fixed(tmp2, t->recent_cpu);
		t->recent_cpu = add_fixed_int(tmp3, t->nice);
	}
	return;
}

// HS 1-6-3. 시스템의 load_avg를 계산하는 함수
// (59/60)*load_avg + (1/60) * ready_threads
void calculate_load_avg (void) {
	int ready_threads = 0;
	ready_threads = list_size(&ready_list);

	if (thread_current() != idle_thread) {
		ready_threads += 1;
	}

	int tmp1 = multiple_fixed_int(load_avg, 59);
	int tmp2 = divide_fixed_int(tmp1, 60);
	int tmp3 = divide_fixed_fixed(convert_int_to_fixed(1), convert_int_to_fixed(60));
	int tmp4 = multiple_fixed_int(tmp3, ready_threads);
	load_avg = add_fixed_fixed(tmp2, tmp4);
}

// HS 1-6-4. 매 틱마다 실행되고 있는 스레드의 recent_cpu가 1씩 증가
void update_recent_cpu (void) {
	if (thread_current() != idle_thread) {
		thread_current()->recent_cpu = add_fixed_int(thread_current()->recent_cpu, 1);
	}
}

// HS 1-6-5. 4 tick마다 모든 스레드의 우선순위 재계산
void recalculate_priority (void) {
	struct list_elem * elem;

	for (elem = list_begin(&sleep_list); elem != list_end(&sleep_list); elem = list_next(elem)) {
		struct thread * t = list_entry(elem, struct thread, elem);
		calculate_priority(t);
	}
	for (elem = list_begin(&ready_list); elem != list_end(&ready_list); elem = list_next(elem)) {
		struct thread * t = list_entry(elem, struct thread, elem);
		calculate_priority(t);
	}
	calculate_priority(thread_current());
}

// HS 1-6-6. 1초마다 모든 스레드의 recent_cpu 재계산
void recalculate_recent_cpu (void) {
	struct list_elem * elem;

	for (elem = list_begin(&sleep_list); elem != list_end(&sleep_list); elem = list_next(elem)) {
		struct thread * t = list_entry(elem, struct thread, elem);
		calculate_recent_cpu(t);
	}
	for (elem = list_begin(&ready_list); elem != list_end(&ready_list); elem = list_next(elem)) {
		struct thread * t = list_entry(elem, struct thread, elem);
		calculate_recent_cpu(t);
	}
	calculate_recent_cpu(thread_current());
}