#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);



struct page_info {
    struct file * file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    //For file_page
    bool first;
    int left_page;

};

#endif /* userprog/process.h */
