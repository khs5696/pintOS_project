#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"
// #include "userprog/process.h"

struct page;
enum vm_type;

struct file_page {
	bool is_first;
	int left_page;

	// munmap에서 사용할 정보
	// 어떤 파일을 reopen할 것인지?
	struct file * file;
	// 업데이트가 되었다면 어디서부터 다시 작성해야 하는지?
	off_t ofs;
	// 얼마 만큼의 내용을 다시 작성하면 되는가?
	uint32_t act_read_bytes;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
