/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// 3-5-1. Swap disk 설정 및 Swap disk 관리를 위한 data structure(=bitmap) 선언
	// disk_get(1, 1) : swap을 위한 disk 할당?
	// bitmap에서 하나의 비트가 swap disk의 swap slot 하나에 매칭되도록 bitmap 선언이 필요
	// -> swap disk의 size를 알아야함.
	// disk_size = disk의 size를 sector단위로 리턴. (DISK_SECTOR_SIZE = 512)
	// bitmap_create(num) : num 길이의 bitmap 생성
	swap_disk = NULL;
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	// 3-5-2. anon_page swapping을 관리하기 위해 swap_table에서 이용할 정보 추가
	// swap_table에서 index를 나타내고, -1은 초기화가 아직 되지 않은 상태를 의미하는 것 같은데,
	// 이 방법 말고 0으로 한 다음에 index는 1부터 시작하고 나중에 swap_table에서 검색할 때는 무조건 swap_idx - 1
	// 로 검색하게 해도 되지 않을까....?
	anon_page->swap_idx = -1;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	// 3-5-4. anonymous page의 swap_in 구현
	// vm_do_claim_page()에서 호출됨
	// page에 저장된 swap_table에서의 index를 이용해, swap_disk에서 데이터를 가져옴
	// -> disk_read (struct disk *d, disk_sector_t sec_no, void *buffer)
	//	  : disk "d"의 "sec_no"에 있는 데이터를 "buffer"에 작성, "buffer"는 반드시 크기가 DISK_SECTOR_SIZE 여야함.
	//  데이터를 swap_disk로부터 memory로 가져오면, swap_table을 수정
	// -> bitmap_set_multiple (struct bitmap *b, size_t start, size_t cnt, bool value)
	//	  : "b"의 "start"부터 "cnt"개의 연속적인 bit를 "value"로 저장

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	// 3-5-3. anonymous page의 swap_out 구현
	// swap_table(=bitmap)에서 bit가 0인 것 하나 찾아야 함
	// -> bitmap_scan_and_flip (struct bitmap *b, size_t start, size_t cnt, bool value)
	// 	  : "b"의 "start"부터 시작해서 "cnt"개 만큼 연속적으로 "value"를 갖는 위치 찾고, 그 bit를 반전시킨 다음에 첫 위치 반환
	// bitmap에서 찾은 bit에 대응되는 swap slot에 다가 page를 입력
	// -> disk_write (struct disk *d, disk_sector_t sec_no, const void *buffer)
	//    : disk "d"의 "sec_no"에 "buffer"를 작성, "buffer"는 반드시 크기가 DISK_SECTOR_SIZE 여야함.
	//	  : 하나의 페이지는 8 sector 크기니까 8번 loop 돌면서 disk_write하면 될 듯?
	// data의 위치는 page에 저장되어야 함.
	// pml4에서 해당 페이지 지우기 & page->frame NULL로 변경
	// 만약 disk에서 비어있는 sector 가져오기 했는데 실패하면 PANIC
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (page->frame)
		free(page->frame);
	if(page->anon.aux) //?stack didn't malloc for aux structure
		free(page->anon.aux);
}
