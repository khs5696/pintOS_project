#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
void check_address (void * addr);

struct lock filesys_lock;

int write(int fd, const void *buffer, unsigned size);
#endif /* userprog/syscall.h */
