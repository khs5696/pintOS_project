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

		// if(aux != NULL)
		// 	printf("file length in vm_alloc_page_with_initializer aux->file %d\n", file_length(((struct page_info *)aux)->file));

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* HS 3-1-3. page(VM_UNINIT) 생성 및 spt에 삽입 */
		// process.c의 Load_segment()에서 호출
		// vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, aux)

		// malloc을 사용해 새로운 page를 할당
		struct page* new_page = (struct page *) malloc(sizeof(struct page));
		ASSERT(new_page);

		// vm_type에 맞는 initializer을 준비
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
		// uninit_new()를 통해 page 구조체를 uninit 상태로 변경(초기화)
		// uninit_new (struct page *page, void *va, vm_initializer *init,
		//		enum vm_type type, void *aux,
		//		bool (*initializer)(struct page *, enum vm_type, void *))
		// printf("upage in vm_alloc_page_with_initializer: %p\n", upage);
		uninit_new(new_page, upage, init, type, aux, initializer);
		new_page->writable = writable;
		new_page->vm_type = type;

		/* TODO: Insert the page into the spt. */
		// spt(hash table)에 생성된 page를 삽입
		// bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED)
		if(spt_insert_page(spt, new_page))
			return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	/* TODO: Fill this function. */
	/* HS 3-1-5. */
	struct page tmp_page;
	// page.va에는 page의 시작 가상 주소가 저장 되어있다. 하지만, parameter va의 값으로
	// 항상 page의 시작 가상 주소가 들어오라는 법은 없고, page 내부에 해당하는 가상 주소
	// 가 argument로 전달될 수 있기 때문에 pg_round_down을 해줘야한다.
	tmp_page.va = pg_round_down(va);

	// supplemental page table에서 va에 해당하는 struct page 탐색
	// struct hash_elem *hash_find (struct hash *, struct hash_elem *)
	struct hash_elem * find_hash_elem = hash_find(&thread_current()->spt.table, &tmp_page.hash_elem);
	if (find_hash_elem)
		return hash_entry(find_hash_elem, struct page, hash_elem);
	else
		return NULL;
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
	if (hash_insert(&spt->table, &page->hash_elem) == NULL)
		succ = true;
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
	void* new_frame = palloc_get_page(PAL_USER);
	if(new_frame == NULL)
		//return vm_evict_frame();
		PANIC("TODO");

	frame = (struct frame *) malloc(sizeof(struct frame));
	if (frame == NULL) 
		PANIC("failed to malloc frame");
	
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
	// printf("vm_try_handle_fault: user = %s, write = %s, not_present = %s\n", user ? "true" : "false", write ? "true" : "false", not_present ? "true" : "false");
	// printf("addr in vm_try_handle_fault: %p\n", addr);
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
	// printf("A\n");
	void *rsp = is_kernel_vaddr(f->rsp) ? thread_current()->save_rsp : f->rsp;
	struct page *page = spt_find_page(spt,addr);
	// printf("B\n");
	if(page){
		// printf("C-1\n");
		// printf("find page's va in vm_try_handler_fault : %p\n", page->va);
		if (page->writable == 0 && write) {
			// printf("page writable false\n");
			return false;
		}
		// printf("D\n");
		return vm_do_claim_page (page);
	}
	else{
		// printf("C-2\n");
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
	// printf("I'm in vm_do_claim_page\n");
	struct frame *frame = vm_get_frame ();
	if (frame == NULL) {
		printf("fail to get frame\n");
		return false;
	}

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* HS 3-2-3. 물리 메모리와의 mapping을 page table에 삽입 */
	// JH : 물리메모리에서 하나의 frame 공간을 배정했다면, page table에서 mapping
	bool writable = page->writable;
	bool check = pml4_set_page(thread_current()->pml4, page->va, frame->kva, writable);
	if (!check) {
		printf("fail to memory allocation\n");
		return false;
	}
	// swap_in : 페이지의 타입이 uninit이면 uninit_initialize(page, frame->kva) 호출
	// 페이지 타입에 따라 페이지를 초기화하고 
	// lazy_load_segment()를 호출해 disk에 있는 file을 물리메모리로 로드
	// list_push_back (&victim_table, &page->victim_elem);
	// printf("uninit_initialize start\n");

	return swap_in (page, frame->kva);
}

// HS 추가
/* Computes and returns the hash value for hash element E, given
 * auxiliary data AUX. */
uint64_t
make_page_hash (const struct hash_elem *e, void *aux) {
	const struct page* page = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&page->va, sizeof(page->va));
}

/* Compares the value of two hash elements A and B, given
 * auxiliary data AUX.  Returns true if A is less than B, or
 * false if A is greater than or equal to B. */
bool
compare_by_page_va (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
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
	hash_init(&spt->table, make_page_hash, compare_by_page_va, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	/* JH . supplemental page table의 내용물을 src에서 dst로 그대로 복사 */
	// __do_fork() 시에 dst에 현재 스레드(=child)의 spt가 들어가고 src에 parent의 spt를 자식에서 그대로 복사하기 위함.
	// src의 모든 element를 순회하면서 정확히 복사해 dst의 supplemental page table에 그대로 넣는다.
	// uninit page를 할당해서 즉시 claim 해야한다.
	ASSERT(src != NULL);
	ASSERT(dst != NULL);

	bool success = true;
	struct hash_iterator i;
	// hash를 이용한 iteration (GitBook Hash Table/Iteration Functions 참고)
	hash_first (&i, &src->table);

	while (hash_next (&i)) {
		struct page * iterate_page = hash_entry (hash_cur (&i), struct page, hash_elem);
		enum vm_type type = iterate_page->operations->type;

		if (VM_TYPE(type) == VM_UNINIT) {
			// vm_type 이 uninit이라는 것은 아직 한번도 필요하지 않아 lazy load가 되지 않은 상황.
			// 따라서 해당 페이지를 그대로 복사해오려면 이후 타입에 맞는 initializer까지 넘겨줘야함. -> vm_alloc_page_with_initializer.
			struct page_info * info = (struct page_info *) malloc(sizeof(struct page_info));
			memcpy(info, iterate_page->uninit.aux, sizeof(struct page_info));
			// 자식 스레드의 spt에 page 복제
			success = vm_alloc_page_with_initializer(iterate_page->vm_type, iterate_page->va, iterate_page->writable, iterate_page->uninit.init, info);
		} else if (VM_TYPE(type) == VM_ANON) {
			// vm_type이 anon인 경우, 이미 initialize가 anon으로 이루어졌고, physical memory에 lazy하게
			// loading도 이루어졌다는 것을 의미함.
			// 자식 스레드의 spt에 똑같은 va를 가리킬 page 복제
			success = vm_alloc_page(VM_ANON|VM_MARKER_0, iterate_page->va, iterate_page->writable);
			// frame 하나 할당해서 위에 vm_alloc_page로 만든 페이지와 연결 / anon_swap_in 실행
			vm_claim_page(iterate_page->va);
			struct page *find_page = spt_find_page (&thread_current()->spt, iterate_page->va);
		
			memcpy(find_page->va, iterate_page->frame->kva, PGSIZE);
		}
		// else if(VM_TYPE(type) == VM_FILE){
		// 	struct page_info* args = (struct page_info*)malloc(sizeof(struct page_info));
		// 	memcpy(args, page->file.aux, sizeof(struct page_info));
		// 	success = vm_alloc_page_with_initializer(VM_FILE, page->va, 
		// 			page->writable, NULL, args);
		// }
	}
	return success;
}

void destroy_and_free_spt_entry(struct hash_elem *e, void *aux){
	struct page* p = hash_entry(e, struct page, hash_elem);
	// vm_dealloc_page() : destroy(page) 하고 free(page) 다 해줌.
	vm_dealloc_page(p);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	// supplemental page table가 쥐고 있는 모든 resource들을 free.
	// process가 exit할 때(userprog/process.c의 process_exit()) 호출됨.
	// page entry를 순회하면서 table의 page마다 destroy(page)를 호출해야한다.
	// 실제 page table(pml4)과 physical memory(palloc-ed memory)를 고려해줄 필요는 없음; 
	// caller는 supplemental page table이 clean up 되고 난 이후에 그것들을 clean 한다.
	hash_destroy(&spt->table, destroy_and_free_spt_entry);
}
