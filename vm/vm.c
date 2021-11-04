/* vm.c: Generic interface for virtual memory objects. */
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/thread.h"
#include "list.h"
#include "threads/palloc.h"
#include <hash.h>
#include "threads/mmu.h"
#include <stdio.h>
#include "userprog/process.h"
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */

	/* HS 3-1-1. supplemental page table(hash table) 초기화 */
	supplemental_page_table_init (&thread_current()->spt);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		/* HS 3-1-3. page(VM_UNINIT) 생성 및 spt에 삽입 */
		// process.c의 Load_segment()에서 호출
		// vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, aux)

		// malloc을 사용해 새로운 page를 할당
		struct page * new_page = palloc_get_page(PAL_USER);
		bool (* page_init_type)(struct page *, enum vm_type, void*);

		// 참고
		new_page->writable = writable;
		new_page->vm_type = type;

		// vm_type에 맞는 initializer을 준비
		switch (VM_TYPE(type)) {
			case VM_ANON :
				page_init_type = anon_initializer;
				break;
			case VM_FILE :
				page_init_type = file_backed_initializer;
				break;
			default :
				PANIC("no type");
				break;
		}

		// uninit_new()를 통해 page 구조체를 uninit 상태로 변경(초기화)
		// uninit_new (struct page *page, void *va, vm_initializer *init,
		//		enum vm_type type, void *aux,
		//		bool (*initializer)(struct page *, enum vm_type, void *))
		uninit_new(new_page, upage, init, type, aux, page_init_type);

		// spt(hash table)에 생성된 page를 삽입
		// bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED)
		if (spt_insert_page(spt, new_page)) {return true;}
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	/* HS 3-1-3. page(VM_UNINIT) 생성 및 spt에 삽입 */
	// supplemental page table에서 va에 해당하는 struct page 탐색
	struct hash_elem * wanted_hash_elem;

	// pg_round_down()을 이용해 가상 메모리 주소(va)에 해당하는 페이지 번호 추출 (한양대 p.304)
	page->va = pg_round_down(va);

	// hash_find() 함수를 이용하여 spt에서 hash_elem 검색 후 반환
	// struct hash_elem *hash_find (struct hash *, struct hash_elem *)
	wanted_hash_elem = hash_find(&spt->spt_table, &page->hash_elem);

	// 참고. 만약 hash_elem이 존재하지 않는다면 NULL 반환
	if (wanted_hash_elem == NULL) {
		return NULL;
	}

	// hash_entry()로 해당 hash_elem의 vm_entry 구조체 리턴
	return hash_entry(wanted_hash_elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	/* HS 3-1-3. page(VM_UNINIT) 생성 및 spt에 삽입 */
	// 해당 virtual address가 이미 존재하고 있는지를 확인해야한다
	// struct hash_elem *hash_insert (struct hash *, struct hash_elem *)
	if (hash_insert(&spt->spt_table, &page->hash_elem) != NULL) {
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	/* HS 3-2-2. 물리 메모리 할당 */
	// vm_do_claim_page()에서 호출되어, palloc_get_page()로 물리 메모리 할당
	// ① palloc_get_page를 호출해 user pool(PAL_USER)로부터 새 물리적 페이지를 할당한다.
	// ② malloc을 호출해 프레임 구조체를 할당 후, 구조체 변수(kva, page)를 초기화하고 반환한다.
	// - 모든 user space page(PALLOC_USER)는 이 함수를 사용해 할당 해야 한다.
	// - 페이지 할당 실패 시 swap out은 처리할 필요 없고, PANIC(“todo”)로 처리
	struct page * new_frame = palloc_get_page(PAL_USER);
	if (new_frame == NULL) 
		PANIC("todo");

	frame = (struct frame*) malloc(sizeof(struct frame));
	
	frame->kva = new_frame;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/* HS 3-2-1. 메모리 접근 및 page fault */
	// exception.c의 page_fault()에 의해 호출 -> vm_try_handle_fault (f, fault_addr, user, write, not_present)
	// not_present를 참조하여 read only 페이지에 대한 접근인지 확인(???)

	// 해당 fault가 유효한 page fault인지 확인 (lazy loading fault)
	// page fault가 발생한 주소(va)에 대한 page를 탐색 -> spt_find_page() 이용
	// page = spt_find_page(spt, addr);

	// 참고
	// if (page->writable == 0 && write) { return false; }

	if(is_kernel_vaddr(addr)) return false;

	void *rsp = is_kernel_vaddr(f->rsp) ? thread_current()->save_rsp : f->rsp;
	page = spt_find_page(spt,addr);

	if(page){
		if (page->writable == 0 && write)
			return false;
		return vm_do_claim_page (page);
	}
	else{
		if(is_kernel_vaddr(f->rsp) && thread_current()->save_rsp){
			rsp = thread_current()->save_rsp;
		}

		// if(user && write && addr > (USER_STACK - (1<<20)) && (int)addr >= ((int)rsp)-32 && addr < USER_STACK){
		// 	vm_stack_growth(addr);
		// 	return true;
		// }
		return false;
	}
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	// ① va에 해당하는 페이지를 supplemental page table에서 탐색
	// ② vm_do_claim_page()를 호출해 탐색으로 얻은 페이지와 새로 할당된 프레임을 mapping
	page = spt_find_page(&thread_current()->spt, va);

	// 참고. Assert ?
	if (page = NULL) { return false; }

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* HS 3-2-3. 물리 메모리와의 mapping을 page table에 삽입 */

	bool writable = page->writable;
	// ① vm_get_frame()으로 새로운 프레임 구조체를 얻는다.
	// ② install_page()를 사용해 argument인 page와 mapping을 추가한다. (pml4_set_page() 함수만 사용하는건?)
	// 		ㄴ 물리메모리에 데이터 적재가 완료되면 pate table에서 mapping
	// install_page(page->va, frame->kva, page->writable);
	int check = pml4_set_page(thread_current()->pml4, page->va, frame->kva, writable);
	// ③ swap_in()로 페이지 타입에 따라 초기화하고, lazy_load_segment()를 호출하여 디스크로부터 데이터를 로드한다.
	// swap_in : 페이지의 타입이 uninit이므로 uninit_initialize(page, frame->kva) 호출
	// 페이지 타입에 따라 페이지를 초기화하고 
	// lazy_load_segment()를 호출해 disk에 있는 file을 물리메모리로 로드

	return swap_in (page, frame->kva);
}

/* HS 3-1-1. supplemental page table(hash table) 초기화를 위한 함수 구현 */
// hash_hash_func : hash 값을 구해주는 함수의 포인터
uint64_t hash_hash_function (const struct hash_elem *e, void *aux){
	// hash_entry()로 element에 대한 페이지 구조체 검색 
	const struct page * tmp = hash_entry(e, struct page, hash_elem);

	// hash_bytes()로 페이지 구조체의 va를 hash value로 변환하여 반환
	// uint64_t hash_bytes (const void *, size_t);
	return hash_bytes(&tmp->va, sizeof(tmp->va));
}

// hash_less_func : hash element 들의 크기를 비교해주는 함수의 포인터 -> hash_find()에서 사용
bool hash_less_function (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	const struct page * a_hash = hash_entry(a, struct page, hash_elem);
	const struct page * b_hash = hash_entry(b, struct page, hash_elem);
	return a_hash->va < b_hash->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* HS 3-1-1. supplemental page table(hash table) 초기화 (한양대 자료 p.300 참고) */
	// 새로운 프로세스가 시작 (initd) 되거나 fork (__do_fork) 될 때 호출
	// bool hash_init (struct hash * h ,hash_hash_func *, hash_less_func *, void *aux)
	// hash_hash_func : hash 값을 구해주는 함수의 포인터
	// hash_less_func : hash element 들의 크기를 비교해주는 함수의 포인터 -> hash_find()에서 사용
	hash_init(&spt->spt_table, hash_hash_function, hash_less_function, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

// hash_destroy()의 parameter인 destructor에 들어갈 함수 선언
// Performs some operation on hash element E, given auxiliary data AUX.
// typedef void hash_action_func (struct hash_elem *e, void *aux);
void hash_destroy_destructor(struct hash_elem * e, void * aux) {
	struct page * destroy_page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(destroy_page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	// 참고. process.c의 process_exit()에서 호출
	// hash_destroy()를 사용해 해시테이블의 버킷리스트와 vm_entry들을 제거 
	// void hash_destroy (struct hash *h, hash_action_func *destructor)
	hash_destroy(spt->spt_table, hash_destroy_destructor);
}
