#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/synch.h"
#include "filesys/off_t.h"

typedef int pid_t;

void syscall_init (void);
void check_address (void * addr);

struct fd_elem {
  int fd;
  struct list_elem elem;
  struct file * file_ptr;
};

// HS 2-2-0. System call 구현을 위한 변수 선언
int current_fd_num;
struct lock file_synch_lock;

// HS 2-2-2. System call 구현
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove (const char * file);
int open(const char * file);
int filesize (int fd);
int read(int fd, const void * buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close(int arg_fd);
void* mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char* name);
bool isdir (int fd);
int inumber (int fd);
int symlink (const char* target, const char* linkpath);
#endif /* userprog/syscall.h */
