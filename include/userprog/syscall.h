#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"

void syscall_init (void);
void check_address (void * addr);

struct lock filesys_lock;

void halt(void);
void exit(int status);
//bool create(const char *file, unsigned initial_size);
int write(int fd, const void *buffer, unsigned size);
#endif /* userprog/syscall.h */
