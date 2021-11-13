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

static struct swap_table swap_anon_table;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// 3-5-1. Swap disk 설정 및 Swap disk 관리를 위한 data structure(=bitmap) 선언
	// bitmap에서 하나의 비트가 swap disk의 swap slot 하나에 매칭되도록 bitmap 선언이 필요
	// -> swap disk의 size를 알아야함.
	
	// disk_get(1, 1) : swap을 위한 disk 할당
	swap_disk = disk_get(1, 1);

	// disk_size = disk의 size를 sector단위로 리턴. (DISK_SECTOR_SIZE = 512)
	disk_sector_t swap_disk_sector_size = disk_size(swap_disk);

	// struct bitmap * bitmap_create (size_t bit_cnt)
	// bitmap_create(num) : num 길이의 bitmap 생성
	swap_anon_table.bit_table = bitmap_create(swap_disk_sector_size / 8);	// 8 sector = 1 page
	lock_init(&swap_anon_table.swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	// 3-5-2. anon_page swapping을 관리하기 위해 swap_anon_table에서 이용할 정보 추가
	// swap_anon_table에서 index를 나타내고, -1은 초기화가 아직 되지 않은 상태를 의미하는 것 같은데,
	// 이 방법 말고 0으로 한 다음에 index는 1부터 시작하고 나중에 swap_anon_table에서 검색할 때는 무조건 swap_table_index - 1
	// 로 검색하게 해도 되지 않을까....?
	anon_page->swap_table_index = 10000;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	// 3-5-4. anonymous page의 swap_in 구현
	// vm_do_claim_page()에서 호출됨
	size_t bit_index = NULL;
	int sector_size = PGSIZE / 8;
	int index = 0;

	bit_index = anon_page->swap_table_index;

	// page에 저장된 swap_anon_table에서의 index를 이용해, swap_disk에서 데이터를 가져옴
	// -> disk_read (struct disk *d, disk_sector_t sec_no, void *buffer)
	//	  : disk "d"의 "sec_no"에 있는 데이터를 "buffer"에 작성, "buffer"는 반드시 크기가 DISK_SECTOR_SIZE 여야함.
	while (index < 8) {
		disk_sector_t sector_number = 8 * bit_index + index;
		void * read_buffer = page->frame->kva + index * sector_size;
		disk_read(swap_disk, sector_number, read_buffer);
		index ++;
	}
	//  데이터를 swap_disk로부터 memory로 가져오면, swap_anon_table을 수정
	// -> bitmap_set_multiple (struct bitmap *b, size_t start, size_t cnt, bool value)
	//	  : "b"의 "start"부터 "cnt"개의 연속적인 bit를 "value"로 저장
	bitmap_set_multiple(swap_anon_table.bit_table, bit_index, 1, false);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	// 3-5-3. anonymous page의 swap_out 구현
	// data의 위치는 page에 저장되어야 함.
	// 만약 disk에서 비어있는 sector 가져오기 했는데 실패하면 PANIC
	size_t bit_index = NULL;
	int sector_size = PGSIZE / 8;
	int index = 0;

	// swap_anon_table(=bitmap)에서 bit가 0인 것 하나 찾아야 함
	// -> bitmap_scan_and_flip (struct bitmap *b, size_t start, size_t cnt, bool value)
	// 	  : "b"의 "start"부터 시작해서 "cnt"개 만큼 연속적으로 "value"를 갖는 위치 찾고, 그 bit를 반전시킨 다음에 첫 위치 반환
	lock_acquire (&swap_anon_table.swap_lock);
	bit_index = bitmap_scan_and_flip (swap_anon_table.bit_table, 0, 1, false);
	anon_page->swap_table_index = bit_index;
	lock_release (&swap_anon_table.swap_lock);

	// bitmap에서 찾은 bit에 대응되는 swap slot에다가 page를 입력
	// -> disk_write (struct disk *d, disk_sector_t sec_no, const void *buffer)
	//    : disk "d"의 "sec_no"에 "buffer"를 작성, "buffer"는 반드시 크기가 DISK_SECTOR_SIZE 여야함.
	//	  : 하나의 페이지는 8 sector 크기니까 8번 loop 돌면서 disk_write하면 될 듯?
	while (index < 8) {
		disk_sector_t sector_number = 8 * bit_index + index;
		void * read_buffer = page->frame->kva + index * sector_size;
		disk_write(swap_disk, sector_number, read_buffer);
		index ++;
	}

	// pml4에서 해당 페이지 지우기 & page->frame NULL로 변경
	pml4_clear_page(thread_current()->pml4, page->va);
	page->frame = NULL;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	if (page->frame != NULL)
		free(page->frame);

	if (anon_page->aux != NULL) //?stack didn't malloc for aux structure
		free(anon_page->aux);
}
