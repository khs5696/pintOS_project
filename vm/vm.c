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
	// 새로운 프로세스가 시작 (initd) 되거나 fork (__do_fork) 될 때 호출
	// supplemental_page_table_init (struct supplemental_page_table *spt)

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

	ASSERT (VM_TYPE(type) != VM_UNINIT)

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
		
		// vm_type에 맞는 initializer을 준비

		// uninit_new()를 통해 page 구조체를 uninit 상태로 변경(초기화)
		// uninit_new (struct page *page, void *va, vm_initializer *init,
		//		enum vm_type type, void *aux,
		//		bool (*initializer)(struct page *, enum vm_type, void *))

		// spt(hash table)에 생성된 page를 삽입
		// bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED)
		struct page* page = (struct page*)malloc(sizeof(struct page));
		ASSERT(page);

		bool (*initializer)(struct page *, enum vm_type, void *);
		switch(VM_TYPE(type)){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;			
				break;
			default:
				PANIC("###### vm_alloc_page_with_initializer [unvalid type] ######");
				break;
		}

		uninit_new(page, upage, init, type, aux, initializer);
		
		// printf("file length 2 %d\n", file_length(((struct load_args *)aux)->file));
		page->writable = writable;
		page->vm_type = type;

		/* TODO: Insert the page into the spt. */
		if(spt_insert_page(spt, page))
			return true;
	}
err:
	return false;
}


/* Returns the page containing the given virtual address, 
or a null pointer if no such page exists. */
struct page *
page_lookup (const void *address) {
  struct page p;
  struct hash_elem *e;

  p.va = address;
  e = hash_find (&thread_current()->spt.hash_table, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */
	/* HS 3-1-5. */
	// supplemental page table에서 va에 해당하는 struct page 탐색
	// struct hash_elem *hash_find (struct hash *, struct hash_elem *)
	// return page;
	
	return page_lookup(pg_round_down(va));
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	// int succ = false;
	/* TODO: Fill this function. */
	/* HS 3-1-3. page(VM_UNINIT) 생성 및 spt에 삽입 */
	// 해당 virtual address가 이미 존재하고 있는지를 확인해야한다
	// struct hash_elem *hash_insert (struct hash *, struct hash_elem *)
	if(hash_insert(&spt->hash_table, &page->hash_elem) == NULL)
		return true;
	return false;
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
	void* p = palloc_get_page(PAL_USER);
	if(p == NULL)
		// printf("p is null\n");
		return vm_evict_frame();

	frame = (struct frame*)malloc(sizeof(struct frame));
	printf("hello\n");
	printf("frame %d\n", p);
	if (frame == NULL) 
		PANIC("failed to allocate frame");
	
	frame->kva = p;
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
	// struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/* HS 3-2-1. 메모리 접근 및 page fault */
	// exception.c의 page_fault()에 의해 호출
	// vm_try_handle_fault (f, fault_addr, user, write, not_present)
	// not_present를 참조하여 read only 페이지에 대한 접근인지 확인(???)

	// 해당 fault가 유효한 page fault인지 확인 (lazy loading fault)
	// page fault가 발생한 주소(va)에 대한 page를 탐색 -> spt_find_page() 이용

	// return vm_do_claim_page (page);
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	if(is_kernel_vaddr(addr))
    return false;

	void *rsp = is_kernel_vaddr(f->rsp) ? thread_current()->save_rsp : f->rsp;
	struct page *page = spt_find_page(spt,addr);

	if(page){
		if (page->writable == 0 && write) {
			// printf("page writable false\n");
			return false;
		}
		// printf("it's okay\n");
		return vm_do_claim_page (page);
	}
	else{
		// printf("not page\n");
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
	// struct page *page = NULL;
	/* TODO: Fill this function */
	struct page *page = spt_find_page(&thread_current()->spt,va);
	ASSERT(page);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	if (frame == NULL) {
		// printf("frame is NULL\n");
	}
	
	// struct load_args* args = page->uninit.aux;
	// printf("file length 2 %d\n", file_length(args->file));

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* HS 3-2-3. 물리 메모리와의 mapping을 page table에 삽입 */

	// 물리메모리에 데이터 적재가 완료되면 pate table에서 mapping
	bool writable = page->writable;
	int check = pml4_set_page(thread_current()->pml4, page->va, frame->kva, writable);
	// printf("plm4 success\n");
	// swap_in : 페이지의 타입이 uninit이므로 uninit_initialize(page, frame->kva) 호출
	// 페이지 타입에 따라 페이지를 초기화하고 
	// lazy_load_segment()를 호출해 disk에 있는 file을 물리메모리로 로드
	// list_push_back (&victim_table, &page->victim_elem);
	// printf("vm_type : %d\n", page->operations->type);
	bool result = swap_in (page, frame->kva);
	if (result) {
		// printf("swap success\n");
	}
	return result;
}

// HS 추가
/* Computes and returns the hash value for hash element E, given
 * auxiliary data AUX. */
uint64_t page_hash (const struct hash_elem *e, void *aux){
	const struct page* p = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

/* Compares the value of two hash elements A and B, given
 * auxiliary data AUX.  Returns true if A is less than B, or
 * false if A is greater than or equal to B. */
bool page_less (const struct hash_elem *a,
		const struct hash_elem *b,
		void *aux){
	struct page* page_a = hash_entry(a, struct page, hash_elem);
	struct page* page_b = hash_entry(b, struct page, hash_elem);

	return page_a->va < page_b->va;
}


/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* HS 3-1-1. supplemental page table(hash table) 초기화 (한양대 자료 p.300 참고) */
	// bool hash_init (struct hash * h ,hash_hash_func *, hash_less_func *, void *aux)
	// hash_hash_func : hash 값을 구해주는 함수의 포인터
	// hash_less_func : hash element 들의 크기를 비교해주는 함수의 포인터 -> hash_find()에서 사용
	hash_init(&spt->hash_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

void supplemental_page_table_destructor(struct hash_elem *e, void *aux){
	struct page* p = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to thmake
	 e storage. */
	struct hash *h = &spt->hash_table;
	hash_destroy(h, supplemental_page_table_destructor);
}
