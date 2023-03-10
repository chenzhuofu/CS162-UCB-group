#include "userprog/syscall.h"
#include <stdint.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "filesys/filesys.h"
#include "stdio.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "lib/kernel/list.h"

extern process_status_list_t processes;
extern struct lock file_operations_lock;

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    list_init(&processes);
    lock_init(&file_operations_lock);
}

static void verify_vaddr(uint32_t*, void*);
static void verify_block(uint32_t*, uint8_t*, int);
static void verify_string(uint32_t*, char*);
static file_descriptor_t* get_file_descriptor(int fd);

static int sys_open(char* file_name);
static int sys_filesize(int fd);
static int sys_read(int fd, uint8_t* buffer, unsigned size);
static int sys_write(int fd, const uint8_t* buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

static void syscall_handler(struct intr_frame* f UNUSED) {
    uint32_t* args = ((uint32_t*)f->esp);
    struct thread* cur = thread_current();

    /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

    /* printf("System call number: %d\n", args[0]); */

    verify_block(cur->pcb->pagedir, (uint8_t*)&args[0], 4);
    switch (args[0]) {
        case SYS_HALT:
            shutdown_power_off();
            break;

        default:
            goto Check_args1;
    };
    return;

Check_args1:
    verify_block(cur->pcb->pagedir, (uint8_t*)&args[1], 4);
    switch (args[0]) {
        case SYS_EXIT:
            f->eax = args[1];
            sys_exit(args[1]);
            break;

        case SYS_EXEC:
            verify_string(cur->pcb->pagedir, (char*)args[1]);
            f->eax = process_execute((char*)args[1]);
            break;

        case SYS_WAIT:
            f->eax = process_wait(args[1]);
            break;

        case SYS_REMOVE:
            verify_string(cur->pcb->pagedir, (char*)args[1]);
            lock_acquire(&file_operations_lock);
            f->eax = filesys_remove((char*)args[1]);
            lock_release(&file_operations_lock);
            break;

        case SYS_OPEN:
            verify_string(cur->pcb->pagedir, (char*)args[1]);
            lock_acquire(&file_operations_lock);
            f->eax = sys_open((char*)args[1]);
            lock_release(&file_operations_lock);
            break;

        case SYS_FILESIZE:
            lock_acquire(&file_operations_lock);
            f->eax = sys_filesize(args[1]);
            lock_release(&file_operations_lock);
            break;

        case SYS_TELL:
            lock_acquire(&file_operations_lock);
            f->eax = sys_tell(args[1]);
            lock_release(&file_operations_lock);
            break;

        case SYS_CLOSE:
            lock_acquire(&file_operations_lock);
            sys_close(args[1]);
            lock_release(&file_operations_lock);
            break;

        case SYS_PRACTICE:
            f->eax = args[1] + 1;
            break;

        default:
            goto Check_args2;
    }
    return;

Check_args2:
    verify_block(cur->pcb->pagedir, (uint8_t*)&args[2], 4);

    switch (args[0]) {
        case SYS_CREATE:
            verify_string(cur->pcb->pagedir, (char*)args[1]);
            lock_acquire(&file_operations_lock);
            f->eax = filesys_create((char*)args[1], args[2]);
            lock_release(&file_operations_lock);
            break;
        case SYS_SEEK:
            lock_acquire(&file_operations_lock);
            sys_seek(args[1], args[2]);
            lock_release(&file_operations_lock);
            break;
        default:
            goto Check_args3;
    }
    return;

Check_args3:
    verify_block(cur->pcb->pagedir, (uint8_t*)&args[3], 4);
    switch (args[0]) {
        case SYS_READ:
            verify_block(cur->pcb->pagedir, (uint8_t*)args[2], args[3]);
            lock_acquire(&file_operations_lock);
            f->eax = sys_read(args[1], (uint8_t*)args[2], args[3]);
            lock_release(&file_operations_lock);
            break;

        case SYS_WRITE:
            verify_block(cur->pcb->pagedir, (uint8_t*)args[2], args[3]);
            lock_acquire(&file_operations_lock);
            f->eax = sys_write(args[1], (uint8_t*)args[2], args[3]);
            lock_release(&file_operations_lock);
            break;

        default:
            printf("Unknown syscall %d", args[0]);
            process_exit();
    }
}

static void verify_vaddr(uint32_t* pd, void* ptr) {
    if (ptr == NULL || is_kernel_vaddr(ptr) || pagedir_get_page(pd, ptr) == NULL) {
        sys_exit(-1);
    }
}

static void verify_block(uint32_t* pd, uint8_t* ptr, int size) {
    int i;
    for (i = 0; i < size; i++) {
        verify_vaddr(pd, ptr + i);
    }
}

static void verify_string(uint32_t* pd, char* str) {
    do {
        verify_vaddr(pd, str);
    } while (*(str++) != '\0');
}

static file_descriptor_t* get_file_descriptor(int fd) {
    struct thread* cur = thread_current();
    struct list_elem* e;
    for (e = list_begin(cur->pcb->fds); e != list_end(cur->pcb->fds); e = list_next(e)) {
        struct file_descriptor* f = list_entry(e, struct file_descriptor, elem);
        if (f->fd == fd) {
            return f;
        }
    }
    return NULL;
}

void sys_exit(int status) {
    struct process* pcb = thread_current()->pcb;
    pid_t pid = get_pid(pcb);

    for (struct list_elem* e = list_begin(&processes); e != list_end(&processes); e = list_next(e)) {
        process_status_t* p = list_entry(e, process_status_t, elem);
        if (p->pid == pid) {
            p->exited = 1;
            p->exit_status = status;
            break;
        }
    }

    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
    process_exit();
}

static int sys_open(char* file_name) {
    struct file* f = filesys_open(file_name);
    if (f == NULL) {
        return -1;
    }

    struct thread* cur = thread_current();
    struct file_descriptor* fd = malloc(sizeof(struct file_descriptor));
    if (fd == NULL) {
        printf("Malloc failed.");
        process_exit();
    }
    fd->file = f;
    fd->fd = cur->pcb->next_fd++;
    list_push_back(cur->pcb->fds, &(fd->elem));
    return fd->fd;
}

static int sys_filesize(int fd) {
    file_descriptor_t* f = get_file_descriptor(fd);
    return (f == NULL ? -1 : file_length(f->file));
}

static int sys_read(int fd, uint8_t* buffer, unsigned size) {
    if (fd == STDIN_FILENO) {
        for (unsigned i = 0; i < size; i++) {
            buffer[i] = input_getc();
        }
        return size;
    } else {
        file_descriptor_t* f = get_file_descriptor(fd);
        if (f == NULL) {
            return -1;
        } else {
            return file_read(f->file, buffer, size);
        }
    }
}

static int sys_write(int fd, const uint8_t* buffer, unsigned size) {
    if (fd == STDOUT_FILENO) {
        putbuf((const char*)buffer, size);
        return size;
    } else {
        file_descriptor_t* f = get_file_descriptor(fd);
        if (f == NULL) {
            return -1;
        } else {
            return file_write(f->file, buffer, size);
        }
    }
}

static void sys_seek(int fd, unsigned position) {
    file_descriptor_t* f = get_file_descriptor(fd);
    if (f != NULL) {
        file_seek(f->file, position);
    }
}

static unsigned sys_tell(int fd) {
    file_descriptor_t* f = get_file_descriptor(fd);
    if (f == NULL) {
        return -1;
    } else {
        return file_tell(f->file);
    }
}

static void sys_close(int fd) {
    file_descriptor_t* f = get_file_descriptor(fd);
    if (f != NULL) {
        file_close(f->file);
        list_remove(&(f->elem));
        free(f);
    }
}
