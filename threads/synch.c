/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		// HS 1-3-1. 실행 중인 스레드가 CA를 사용하고자 할 때
		// 우선순위에 따라 정렬하여 sema의 waiters 리스트에 삽입한다.
		list_insert_ordered(&sema->waiters, &thread_current ()->elem, compare_by_priority, NULL);

		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters)) {
		struct thread * t;
		// HS 1-3-2. 공유자원을 사용하기 위해 waiters에서 스레드 한 개를 unblock한다.
		// waiters에서 대기 중일 때, 우선순위가 변경될 수도 있으므로 unblock하기 전에 정렬하낟.		
		list_sort(&sema->waiters, compare_by_priority, NULL);

		t = list_entry(list_pop_front(&sema->waiters), struct thread, elem);
		thread_unblock(t);
		sema->value++;
		if(t->priority > thread_get_priority()) {
			// 공유자원을 사용하기 위해 대기 중인 스레드가 있다면, waiters에서 선점한다.
			thread_yield();
		}
	}else {
		sema->value++;
	}
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	// HS 1-6-8. advanced scheduler 사용 시 donation 통제
	if (thread_mlfqs) {
		sema_down(&lock->semaphore);
		lock->holder = thread_current();
		return;
	}

	// 1-5-1. 실행 중인 스레드가 lock_acquire으로 lock을 요청할 때, 
	// 다른 스레드(holder)가 요청한 lock을 사용하고 있다면
	// donation과 관련된 변수(waiting_lock, donated)를 업데이트하고
	// lock->holder에게 우선순위를 양보한다.
	if(lock->holder != NULL) {
		thread_current()->waiting_lock = lock;				// 실행 중인 스레드의 waiting_lock 업데이트
		list_insert_ordered(&lock->holder->donated, 		// holder의 donated에 우선순위에 따라 삽입
			&thread_current()->donated_elem, 
				cmp_donate_priority, 0);

		donate_priority();
	}
	sema_down (&lock->semaphore);

	thread_current()->waiting_lock = NULL;
	lock->holder = thread_current ();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	// HS 1-6-8. advanced scheduler 사용 시 donation 통제
	if (thread_mlfqs) {
		lock->holder = NULL;
		sema_up(&lock->semaphore);
		return;
	}

	// HS 1-5-3. 우선순위를 양보받은 스레드의 작업이 완료되면
	// donation과 관련된 변수(donated) 업데이트 = 양보받은 스레드를 제거
	donated_update(lock);
	// donated 리스트중 가장 큰 값으로 우선 순위를 재설정한다.
	reset_priority();

	lock->holder = NULL;
	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	// HS 1-4-1. 우선순위에 따라 스레드를 실행하되, cond->waiters를 구성하는 세마포어의
	// waiter(대기 중인 스레드 목록)는 내림차순으로 정렬이 이미 완료된 상태이므로
	// 세마포어->waiter의 첫번째 스레드끼리 우선 순위를 비교하여 삽입한다.
	list_insert_ordered (&cond->waiters, &waiter.elem, compare_by_sema_elem_priority, 0);

	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
		// HS 1-4-2. cond_wait에서 block 되어 대기하는 도중에 스레드의 우선순위가 바뀌는 경우
		// 세마포어의 waiter 내부에서는 sema_up에 의해 정렬이 이미 완료되었으므로
		// 세마포어의 첫 번째 요소들끼리 비교해 정렬한다.
		list_sort(&cond->waiters, compare_by_sema_elem_priority, NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}


// HS 1-3-0. semaphore의 waiter(대기 중인 스레드 리스트)는 
// sema_up과 sema_down에 의해 이미 정렬되어 있는 상태
// 세마포어 waiter의 첫번째 스레드끼리 우선순위를 비교하여 정렬 및 삽입하기 위해
// 인자로 사용 될 함수를 선언한다.
// typedef bool list_less_func (const struct list_elem *a, const struct list_elem *b, void *aux);
bool
compare_by_sema_elem_priority (const struct list_elem *a, const struct list_elem *b, void *aux) {
	struct semaphore_elem * sema_a = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem * sema_b = list_entry(b, struct semaphore_elem, elem);

	int sema_a_first = list_entry (list_begin (&(sema_a->semaphore.waiters)), struct thread, elem)->priority;
	int sema_b_first = list_entry (list_begin (&(sema_b->semaphore.waiters)), struct thread, elem)->priority;
	// printf("sema_a_first: %d, sema_b_first: %d\n", sema_a_first, sema_b_first);
	return sema_a_first > sema_b_first;
}
