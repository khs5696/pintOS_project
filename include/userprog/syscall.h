#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

typedef int pid_t;

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
int filesize (int fd);
int read(int fd, const void * buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void close(int arg_fd);
#endif /* userprog/syscall.h */