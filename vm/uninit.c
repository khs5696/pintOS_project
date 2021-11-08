/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"
#include "userprog/process.h"


static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);
	// if(aux != NULL)
	// 	printf("file length in uninit_new aux->file %d\n", file_length(((struct page_info *)aux)->file));

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	// JH : setup_stack 할 때 vm_alloc_page를 호출함.
	// vm_alloc_page(type, upage, writable) == vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
	// 때문에 이 경우 init과 aux가 NULL인 상태!
	vm_initializer *init = uninit->init;
	struct page_info * aux = uninit->aux;
	// if (aux != NULL) {
	// 	printf("file length in uninit_initialize uninit->aux->file %d\n", file_length( ((struct page_info *)aux)->file ));
	// }

	/* TODO: You may need to fix this function. */
	/* HS 3-2-4. 물리 메모리에 데이터 로드 */
	// vm_do_claim_page()에서 호출		swap_in (page, frame->kva)
	// 변수 init에는 NULL이 아니라면, vm_alloc_page_with_initializer()에 의해 lazy_load_segment() 존재
	// 변수 page_initializer에는 페이지 타입에 맞는 initializer 존재
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: Fill this function.
	 * TODO: If you don't have anything to do, just return. */
	free(uninit->aux);
}
