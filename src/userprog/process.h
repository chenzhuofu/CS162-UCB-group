#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include "list.h"

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

typedef struct process_status {
    pid_t pid;
    int exited, exit_status; /* Exit status */
    struct list_elem elem;
} process_status_t;
typedef struct list process_status_list_t;

/* List storing all child processes pointer. */
typedef struct child_process {
    process_status_t* status;
    struct list_elem elem;
} child_process_t;
typedef struct list child_process_list_t;

typedef struct file_descriptor {
    int fd;
    struct file* file;
    struct list_elem elem;
} file_descriptor_t;
typedef struct list file_descriptor_list_t;

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
    /* Owned by process.c. */
    uint32_t* pagedir;          /* Page directory. */
    char process_name[16];      /* Name of the main thread */
    struct thread* main_thread; /* Pointer to main thread */

    child_process_list_t* children; /* List of child processes */
    file_descriptor_list_t* fds;  /* List of open files */
    int next_fd;               
};

void userprog_init(void);

pid_t process_execute(const char* task);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
