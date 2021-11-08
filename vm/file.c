/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

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
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

// /* Do the mmap */
// void *
// do_mmap (void *addr, size_t length, int writable,
// 		struct file *file, off_t offset) {
// 	// JH 3-4-2 mmap에서 사용할 do_mmap 구현
// 	// mapping의 범위가 이미 존재하고 있던 page를 덮어버리려고 하는 경우 실패 -> NULL 리턴
// 	// load_segment와 유사한 과정
// 	ASSERT(addr != NULL);
// 	ASSERT(length != 0);
// 	ASSERT(file != NULL);
// 	ASSERT(pg_round_down(addr) == addr);

// 	void * tmp_addr = addr;
// 	uint32_t read_bytes = length > file_length(file) ? file_length(file) : length;
// 	uint32_t zero_bytes = pg_round_up(read_bytes) - read_bytes;

// 	while(read_bytes > 0 || zero_bytes > 0) {
// 		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
// 		size_t page_zero_bytes = PGSIZE - page_read_bytes;

// 		struct () * aux = () malloc(sizeof());
// 		// 값 할당 과정
// 		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
// 					writable, lazy_load_segment, aux))
// 			return NULL;
		
// 		/* Advance. */
// 		read_bytes -= page_read_bytes;
// 		zero_bytes -= page_zero_bytes;
// 		addr += PGSIZE;
// 		offset += page_read_bytes;
// 	}
// 	return save_addr;
// }

// /* Do the munmap */
// void
// do_munmap (void *addr) {
// }
