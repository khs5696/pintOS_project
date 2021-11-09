/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "filesys/file.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	struct page_info* info = page->uninit.aux;
	page->operations = &file_ops;

	// JH 이후 munmap할 때 편의를 위해 페이지마다 
	// segment의 첫번째 페이지인지, 앞으로 남은 페이지가 몇 개인지,
	// 어떤 파일에 어디서부터 저장할 지에 대한 정보를 추가 저장.
	struct file_page *file_page = &page->file;
	file_page->is_first = info->first;
	file_page->left_page = info->left_page;
	file_page->file = info->file;
	file_page->ofs = info->ofs;
	file_page->act_read_bytes = info->read_bytes;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	// 3-5-6. file-backed page의 swap_in 구현
	// 그냥 page에 저장된 file에 대한 정보 가지고 kva에 다시 lazy_load_segment하면 될 듯?
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	// 3-5-5. file-backed page의 swap_out 구현
	// vm_do_claim_page()에서 호출됨
	// file_backed_destroy와 비슷하게 dirty_bit 확인하고 file_seek, file_write
	// page가 수정된 이력이 있는지 확인해서 만약 없다면, 굳이 파일에 덮어쓰기 할 필요 없음
	// -> pml4_is_dirty(uint64_t *pml4, const void *vpage)
	//	  : "pml4"에서 "vpage"에 해당하는 PTE의 dirty bit 확인
	// pml4에서 해당 PTE의 dirty_bit를 다시 0으로 만들어 줘야함.
	// -> pml4_set_dirty (uint64_t *pml4, const void *vpage, bool dirty)
	//	  : "pml4"의 "vpage"에 해당하는 PTE의 dirty_bit를 "dirty"로 변경
	// pml4에서 해당 페이지 지우기 & page->frame NULL로 변경
	// -> pml4_clear_page (uint64_t *pml4, void *upage)
	//	  : "pml4"의 "upage"의 not_present를 true로 변경해주는 함수
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	// do_munmap()에서 destroy_and_free_spt_entry()를 호출하면 이 함수가 호출 됨
	// 만약 memory에 load한 content가 수정된 적이 있다면(pml4_is_dirty()로 확인),
	// 그 내용을 파일에 다시 적어줘야하고, 아니라면 memory만 0으로 초기화 시켜주면 됨.
	struct file_page *file_page = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {	// 만약 수정한 이력이 있다면
		file_seek(file_page->file, file_page->ofs);
		file_write(file_page->file, page->va, file_page->act_read_bytes);
	}
	memset(page->va, 0, PGSIZE);

	if(page->frame != NULL)
		free(page->frame);
	// free(file_page);
}
// aux로 사용한 것들 page에 저장했으면 free 해줘야함!!!!!!



static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */

	/* HS 3-2-4. 실제로 page와 연결된 물리 메모리에 데이터 로드 */
	// uninit.c의 uniuninit_initialize()에서 호출
	uint8_t* pa = (page->frame)->kva;
	struct page_info* info = aux;
	// file의 pointer를 info->ofs로 옮김으로써 앞으로 file을 읽을 때
	// 원하는 위치인 ofs부터 읽도록 만듦.
	file_seek(info->file, info->ofs);

	int read_byte = file_read (((struct page_info *)info)->file, pa, info->read_bytes);
	// printf("a %d\n", read_byte);
	// printf("c %d\n", pa);
	// printf("b %d\n", (int) info->read_bytes);
	if (read_byte != (int) info->read_bytes) {
		// printf("lazy fail\n");
		palloc_free_page (pa);
		return false;
	}
	memset(pa + info->read_bytes, 0, info->zero_bytes);
	free(aux);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// JH 3-4-2 mmap에서 사용할 do_mmap 구현
	// mapping의 범위가 이미 존재하고 있던 page를 덮어버리려고 하는 경우 실패 -> NULL 리턴
	// load_segment와 유사한 과정
	ASSERT(addr != NULL);
	ASSERT(length != 0);
	ASSERT(file != NULL);
	ASSERT(pg_round_down(addr) == addr);

	bool first = true;

	void* tmp_addr = addr;
	// read_bytes : 총 읽어야할 byte의 수
	uint32_t read_bytes = length > file_length(file) ? file_length(file) : length;
	// zero_bytes : page 단위로 맞춰야하기 때문에 남는 공간을 채울 0의 byte 수
	uint32_t zero_bytes = pg_round_up(read_bytes) - read_bytes;
	// page_num 앞으로 할당할 page(or frame)의 수
	int page_num = (int)pg_round_up(read_bytes)/PGSIZE - 1;

	// 앞으로 넣을 공간에 이미 어떤 데이터가 있는 지 미리 확인
	for (int i = 0; i <= page_num; i++) {
		if(spt_find_page(&thread_current()->spt, addr + i*PGSIZE))
			return NULL;
	}

	while(read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct page_info * aux = (struct page_info *) malloc(sizeof(struct page_info));
		// 값 할당 과정
		struct file * dup_file = file_reopen(file);
		aux->file = dup_file;
		aux->ofs = offset;
		offset += page_read_bytes;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		aux->first = first;
		if (first)
			first = false;
		aux->left_page = page_num;
		page_num -= 1;

		if (!vm_alloc_page_with_initializer (VM_FILE, tmp_addr,
					writable, lazy_load_segment, aux))
			return NULL;
		
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		tmp_addr += PGSIZE;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	struct supplemental_page_table * spt = &thread_current()->spt;
	struct page * first_page_to_munmap = spt_find_page(spt, addr);

	struct file* dup_file = first_page_to_munmap->file.file;

	ASSERT(pg_round_down(addr) == addr);
	ASSERT(first_page_to_munmap->file.is_first);

	int num_to_munmap = first_page_to_munmap->file.left_page;
	// printf("num of munmap: %d\n", num_to_munmap);
	for(int i = 0; i <= num_to_munmap; i++) {
		// printf("%d\n", i);
		struct page * delete_page = spt_find_page(spt, addr + i*PGSIZE);
		if(delete_page == NULL)
			PANIC("There is no mmap page!");
		hash_delete(&spt->table, &delete_page->hash_elem);
		destroy_and_free_spt_entry(&delete_page->hash_elem, NULL);
	}
	file_close(dup_file);
}
