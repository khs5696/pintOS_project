#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
#include "threads/synch.h"
#include <bitmap.h>
// #include "userprog/process.h"

struct page;
enum vm_type;

struct anon_page {
	void* padding;
	enum vm_type type;
	struct page_info *aux;
  	int swap_idx;
};

struct swap_table {
	struct lock lock;
	struct bitmap * bit_map;
};


void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
