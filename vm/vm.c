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

struct list victim_table;

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
	list_init(&victim_table);

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
// JH do_mmap에서 vm_alloc_page_with_initializer(VM_FILE, tmp_addr, writable, lazy_load_segment, aux) 로 호출됨
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
		struct page* new_page;
		new_page = (struct page *) malloc(sizeof(struct page));
		// struct page * new_page = (struct page *)palloc_get_page(PAL_USER);
		// JH 이거 원래 ASSERT였음
		if(new_page == NULL)
			return false;
	
		bool (* page_type_init) (struct page *, enum vm_type, void *);
		// vm_type에 맞는 initializer을 준비
		switch(VM_TYPE(type)){
			case VM_FILE:	// 백업을 위한 저장소 O
				page_type_init = file_backed_initializer;			
				break;
			case VM_ANON:	// 백업을 위한 저장소 X
				page_type_init = anon_initializer;
				break;
			default:		// 잘못된 타입 입력
				PANIC("###### vm_alloc_page_with_initializer [unvalid type] ######");
				break;
		}
		// uninit_new()를 통해 page 구조체를 uninit 상태로 변경(초기화)
		// uninit_new (struct page *page, void *va, vm_initializer *init,
		//		enum vm_type type, void *aux,
		//		bool (*initializer)(struct page *, enum vm_type, void *))
		// printf("upage in vm_alloc_page_with_initializer: %p\n", upage);
		uninit_new(new_page, upage, init, type, aux, page_type_init);	// uninit으로 초기화

		// new_page 관련 변수 업데이트
		new_page->vm_page_type = type;		// 페이지의 실제 타입 (초기에는 uninit)
		new_page->writable = writable;	// 수정 가능 여부

		/* TODO: Insert the page into the spt. */
		// spt(hash table)에 생성된 page를 삽입
		// bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED)
		bool check_insert = spt_insert_page(spt, new_page);

		if(check_insert == true) 
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
	struct hash_elem * find_hash_elem = hash_find(&thread_current()->spt.table, &tmp_page.hash_page_elem);

	if (find_hash_elem)
		return hash_entry(find_hash_elem, struct page, hash_page_elem);
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
	if (hash_insert(&spt->table, &page->hash_page_elem) == NULL)
		succ = true;
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	/* TODO: The policy for eviction is up to you. */
	struct page * victim_page;
	struct list_elem * victim_page_elem;
	struct list_elem * head_page_elem;
	struct list_elem * tail_page_elem;

	head_page_elem = list_front(&victim_table);
	tail_page_elem = list_end(&victim_table);

	// frame table을 순회하면서 우선순위에 따라 제거(swap out)할 frame 탐색
	victim_page_elem = head_page_elem;

	while (1) {
		victim_page = list_entry (victim_page_elem, struct page, victim_page_elem);

		bool check_access = pml4_is_accessed(&thread_current()->pml4, victim_page->va);
		// 해당 페이지를 아직 접근하지 않은 경우 (access bit = 0)
		if (check_access == false) {
			victim = victim_page->frame;
			// frame table에서 제거(swap out)
			list_remove(victim_page_elem);
			return victim;
		} 
		// 해당 페이지를 이미 접근한 경우 (access bit = 1)		
		else {
			// 해당 페이지의 access bit를 0으로 초기화하고 다음 페이지 탐색
			pml4_set_accessed(&thread_current()->pml4, victim_page->va, 0);
			victim_page_elem = list_next(victim_page_elem);

			// frame table을 끝까지 순회한 경우, 처음부터 다시 순히하며 탐색
			if (victim_page_elem == tail_page_elem) {
				victim_page_elem = head_page_elem;
			}
		}
	}
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	struct page * victim_page = victim->page;
	/* TODO: swap out the victim and return the evicted frame. */
	// 제거할 frmae이 결정되면 swap out
	bool check_swap = swap_out(victim_page);
	ASSERT(check_swap);

	victim->page = NULL;	// swap out된 frame의 page는 NULL로 초기화

	return victim;
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
	void * new_frame = palloc_get_page(PAL_USER);

	if(new_frame == NULL) {	// 메모리가 가득 차서 새로 프레임을 추가할 수 없는 상태
		frame = vm_evict_frame();
		return frame;
	}

	// 새로 할당된 물리 메모리와 페이지를 연결시키기 위해 프레임 구조체 선언
	frame = (struct frame *) malloc(sizeof(struct frame));
	ASSERT (frame != NULL);

	frame->page = NULL;
	frame->kva = new_frame;
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// JH 3-3-2. stack의 size를 증가시켜 addr가 fault가 안 일어나게끔 해야한다.
	// setup_stack에서 했던 것과 매우 유사 = vm_alloc_page하고 바로 vm_claim_page해서 0으로 memset
	// addr를 valid pointer로 만들기 위해 2개 이상의 page를 할당해야할 수 있음으로, 충족될 때까지 계속 위 과정 반복
	struct supplemental_page_table * spt_table = &thread_current ()->spt;
	struct page * stack_page;
	void * normal_addr;

	// 이걸 page 수를 계산해서 for문으로 돌릴 수도 있지 않을까?
	// addr를 PGSIZE만큼 반올림 해서 사용해야한다. => pg_round_down()
	normal_addr = pg_round_down(addr);

	while((stack_page = spt_find_page(spt_table, normal_addr) == NULL)) {
		// 주어진 normal_addr로 spt_find_page를 했는데 발견 못 함
		// => 새로운 stack page 할당
		if(!(vm_alloc_page(VM_ANON | VM_MARKER_0, normal_addr, true) && vm_claim_page(normal_addr))) {
			// struct page * p = spt_find_page(spt_table, addr);
			palloc_free_page(stack_page);
			PANIC("Can't allocate page or frame for growing stack");
		}
		memset(normal_addr, 0, PGSIZE);

		normal_addr = normal_addr + PGSIZE;
	}
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
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/* HS 3-2-1. 메모리 접근 및 page fault */
	// exception.c의 page_fault()에 의해 호출
	// vm_try_handle_fault (f, fault_addr, user, write, not_present)

	// JH page fault가 발생하는 원인
	// - user program이 kernel virtual memory에 접근하려고 할 때 (USER PROGRAMS/Introduction/Virtual Memory Layout)
	// - kernel에서 unmapped user virtual address에 접근하려고 할 때
	// - 모든 invalid access
	// invalid access (GitBook Virtual Memory/Introduction/Handling page fault)
	// -> process를 terminate 시켜야함.
	// 1. spt를 확인 했을 때도 없는 address에 접근하려고 할 때
	// 2. user가 kernel virtual memory의 page를 읽으려고 할 때
	// 3. read_only page에 write 하려고 할 때 => not_present가 false

	// system_call과 user에 의한 page_fault는 intr_frame f에 rsp가 저장되어있음
	// stack pointer는 user에서 kernel로 context switch가 일어날 때만 저장함으로 rsp가 undefined 일 수도 있음

	// 해당 fault가 유효한 page fault인지 확인 (lazy loading fault)
	// page fault가 발생한 주소(va)에 대한 page를 탐색 -> spt_find_page() 이용

	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;

	void * stack_pointer = NULL;
	void * user_rsp = thread_current()->user_stack_pointer;

	if(user && is_kernel_vaddr(addr)) // JH kernel virtual address에 접근하려고 할 때? user에서 발생한 fault인지 봐야하지 않을까?
    	return false;
	// JH f로 들어온 intr_frame이 kernel에서 발생했을 수도 있기 때문에? user의 stack pointer를 가져오기 위함.
	// user_stack_pointer (x) thread_current()->fork_intr.rsp (o)
	if (is_kernel_vaddr(f->rsp))	// kernel에서 interrupt 발생
		stack_pointer = user_rsp;
	else							// user에서 interrupt 발생
		stack_pointer = f->rsp;

	// JH spt에서 addr로 찾아보기
	if ((page = spt_find_page(spt, addr))!= NULL) { // spt에 저장되어 있던 page = 언젠가는 load되어야 하지만 lazy하게 기다리고 있던 page
		// JH read_only page에 write하려고 했던 경우?
		if (write && page->writable == 0) {	return false; }
		// Jh lazy loading
		return vm_do_claim_page (page);
	}
	else {	// spt에 저장이 안되어 있던 page! -> load할 생각이 없었던 page
		// f->rsp에 kernel stack pointer가 저장되어 있고, thread_current()->fork_intr.rsp에 뭔가가 저장되어 있을 때
		// rsp가 user stack pointer를 가리켜주도록!
		// 이거 위에서 똑같이 해준 거 아님? && 이거 해주려면 그럼 thread_current()->fork_intr.rsp를 저장해서 한번 사용했으면 null로 바꿔주는 과정도 필요하지 않을까?
		// if (is_kernel_vaddr(f->rsp) && user_rsp){
		// 	stack_pointer = user_rsp;
		// }

		// JH 3-3-1. Stack Growth를 위한 page fault를 인식하기 위해 조건 추가
		// 이번 과제에서 stack은 최대 1MB(== 1 << 20) 만큼 커질 수 있게 구현
		// addr가 USER_STACK의 밑을 가리켜야함, USER_STACK 위를 가리키고 있으면 그건 그냥 애초에 잘못 된 거
		// USER_STACK = 0x47480000
		// 저 -32는 한양대 163p에 있는 내용인데 우리는 'rsp 8바이트 아래에서 page fault가 발생할 수 있다.'(GitBook Stack Growth)라고 했는데 이게 그건가.....?
		if (user && write) {
			if (addr > (USER_STACK - (1<<20)) && addr < USER_STACK){
				if ((int)addr >= ((int)stack_pointer) - 32) {
					vm_stack_growth(addr);
					return true;
				}
			}
		}
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
	page = spt_find_page(&thread_current()->spt, va);

	if(page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	bool check_success;

	if (frame == NULL)
		return false;

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* HS 3-2-3. 물리 메모리와의 mapping을 page table에 삽입 */
	// JH : 물리메모리에서 하나의 frame 공간을 배정했다면, page table에서 mapping
	if (pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable) == false)
		return false;

	// swap_in : 페이지의 타입이 uninit이면 uninit_initialize(page, frame->kva) 호출
	// 페이지 타입에 따라 페이지를 초기화하고 
	// lazy_load_segment()를 호출해 disk에 있는 file을 물리메모리로 로드
	list_push_back (&victim_table, &page->victim_page_elem);

	return swap_in (page, frame->kva);
}

// hash_hash_func : hash 값을 구해주는 함수의 포인터
uint64_t
make_page_hash (const struct hash_elem *e, void *aux) {
	const struct page * find_page;

	find_page = hash_entry(e, struct page, hash_page_elem);
	return hash_bytes(&find_page->va, sizeof(find_page->va));
}

// hash_less_func : hash element 들의 크기를 비교해주는 함수의 포인터 -> hash_find()에서 사용
bool 
compare_by_page_va (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	struct page* page_a = hash_entry(a, struct page, hash_page_elem);
	struct page* page_b = hash_entry(b, struct page, hash_page_elem);

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
	struct hash_iterator index;		// hash table iteration을 위한 index
	struct page * tmp_page = NULL;
	struct page * find_page = NULL;
	enum vm_type tmp_page_type;
	struct page_info * tmp_page_info = NULL;
	bool result = true;

	/* JH . supplemental page table의 내용물을 src에서 dst로 그대로 복사 */
	// __do_fork() 시에 dst에 현재 스레드(=child)의 spt가 들어가고 src에 parent의 spt를 자식에서 그대로 복사하기 위함.
	// src의 모든 element를 순회하면서 정확히 복사해 dst의 supplemental page table에 그대로 넣는다.
	// uninit page를 할당해서 즉시 claim 해야한다.
	ASSERT(src != NULL);
	ASSERT(dst != NULL);

	// hash를 이용한 iteration (GitBook Hash Table/Iteration Functions 참고)
	hash_first (&index, &src->table);

	while (hash_next (&index)) {	// spt의 처음부터 끝까지 순회
		tmp_page = hash_entry (hash_cur(&index), struct page, hash_page_elem);
		tmp_page_type = tmp_page->operations->type;		// uninit이 아닌 실제 페이지 타입

		switch (VM_TYPE(tmp_page_type)) {
			case VM_UNINIT :
				// vm_type 이 uninit이라는 것은 아직 한번도 필요하지 않아 lazy load가 되지 않은 상황.
				// 따라서 해당 페이지를 그대로 복사해오려면 이후 타입에 맞는 initializer까지 넘겨줘야함. -> vm_alloc_page_with_initializer.
				tmp_page_info = (struct page_info *) malloc (sizeof(struct page_info));
				memcpy(tmp_page_info, tmp_page->uninit.aux, sizeof(struct page_info));	// page_info 복제
				// 자식 스레드의 spt에 page 복제
				if (!vm_alloc_page_with_initializer(tmp_page->vm_page_type, tmp_page->va, tmp_page->writable, tmp_page->uninit.init, tmp_page_info))
					result = false;
				break;

			case VM_ANON :
				// vm_type이 anon인 경우, 이미 initialize가 anon으로 이루어졌고, physical memory에 lazy하게
				// loading도 이루어졌다는 것을 의미함.
				// 자식 스레드의 spt에 똑같은 va를 가리킬 page 복제
				if (!vm_alloc_page(VM_ANON|VM_MARKER_0, tmp_page->va, tmp_page->writable))
					result = false;
				vm_claim_page(tmp_page->va);	// frame 하나 할당해서 위에 vm_alloc_page로 만든 페이지와 연결 / anon_swap_in 실행
				find_page = spt_find_page(&thread_current()->spt, tmp_page->va);
				memcpy(find_page->va, tmp_page->frame->kva, PGSIZE);	// page content 복제
				break;

			case VM_FILE :
				tmp_page_info = (struct page_info*) malloc (sizeof(struct page_info));
				// memcpy(tmp_page_info, tmp_page->file.aux, sizeof(struct page_info));
				tmp_page_info->file = tmp_page->file.file;
				tmp_page_info->ofs = tmp_page->file.ofs;
				tmp_page_info->read_bytes = tmp_page->file.act_read_bytes;
				tmp_page_info->first = tmp_page->file.is_first;
				tmp_page_info->left_page = tmp_page->file.left_page;

				if (!vm_alloc_page_with_initializer(tmp_page->vm_page_type, tmp_page->va, tmp_page->writable, NULL, tmp_page_info))
					result = false;
				break;

			default :
				break;
		}
		// if (VM_TYPE(type) == VM_UNINIT) {
		// 	// vm_type 이 uninit이라는 것은 아직 한번도 필요하지 않아 lazy load가 되지 않은 상황.
		// 	// 따라서 해당 페이지를 그대로 복사해오려면 이후 타입에 맞는 initializer까지 넘겨줘야함. -> vm_alloc_page_with_initializer.
		// 	struct page_info * info = (struct page_info *) malloc(sizeof(struct page_info));
		// 	memcpy(info, tmp_page->uninit.aux, sizeof(struct page_info));
		// 	// 자식 스레드의 spt에 page 복제
		// 	success = vm_alloc_page_with_initializer(tmp_page->vm_type, tmp_page->va, tmp_page->writable, tmp_page->uninit.init, info);
		// } else if (VM_TYPE(type) == VM_ANON) {
		// 	// vm_type이 anon인 경우, 이미 initialize가 anon으로 이루어졌고, physical memory에 lazy하게
		// 	// loading도 이루어졌다는 것을 의미함.
		// 	// 자식 스레드의 spt에 똑같은 va를 가리킬 page 복제
		// 	success = vm_alloc_page(VM_ANON|VM_MARKER_0, tmp_page->va, tmp_page->writable);
		// 	// frame 하나 할당해서 위에 vm_alloc_page로 만든 페이지와 연결 / anon_swap_in 실행
		// 	vm_claim_page(tmp_page->va);
		// 	struct page *find_page = spt_find_page (&thread_current()->spt, tmp_page->va);
		
		// 	memcpy(find_page->va, tmp_page->frame->kva, PGSIZE);
		// }
		// else if(VM_TYPE(type) == VM_FILE){
		// 	struct page_info* args = (struct page_info*)malloc(sizeof(struct page_info));
		// 	memcpy(args, page->file.aux, sizeof(struct page_info));
		// 	success = vm_alloc_page_with_initializer(VM_FILE, page->va, 
		// 			page->writable, NULL, args);
		// }
	}
	return result;
}

void
destroy_and_free_spt_entry(struct hash_elem *e, void *aux) {
	struct page* destroy_page;

	destroy_page = hash_entry(e, struct page, hash_page_elem);	// hash_elem을 page 구조체 형태로 변형
	// vm_dealloc_page() : destroy(page) 하고 free(page) 다 해줌.
	vm_dealloc_page(destroy_page);
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
