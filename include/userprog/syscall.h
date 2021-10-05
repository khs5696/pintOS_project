#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
void check_address (void * addr);

struct fd_elem {
  int fd;
  struct list_elem elem;
  struct file * file_ptr;
};

int fd_cnt;

struct lock filesys_lock;

void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
int open(const char * file);
int write(int fd, const void *buffer, unsigned size);
#endif /* userprog/syscall.h */
