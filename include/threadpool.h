#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <process.h>
#include "config.h"
#include "logger.h"

#ifndef THREADPOOL_H
#define THREADPOOL_H
// linkedlist
typedef struct Task {
    void (*function) (void*);
    void *arg;
    struct Task *next;
} Task;

void init_thread_pool(int n);
void enqueue_task(void (*function)(void*) ,void *arg);
Task* dequeue_task();
unsigned __stdcall work_thread(void *arg);
void shutdown_thread_pool();

#endif