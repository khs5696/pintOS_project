#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
#include <stdbool.h>

void syscall_init (void);
void check_address (void * addr);

struct lock file_lock;

int write(int fd, const void *buffer, unsigned size);
bool create(const char *file, unsigned initial_size);
int open (const char *file);
void exit (int status);
void halt(void);

#endif /* userprog/syscall.h */
