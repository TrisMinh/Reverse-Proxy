#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <windows.h>
#include <process.h>

#define MAX_TASKS 1024

typedef struct {
    void (*func)(void *);
    void *arg;
} Task;

typedef struct {
    HANDLE threads[64];
    int thread_count;

    Task tasks[MAX_TASKS];
    int head;
    int tail;
    int task_count;

    CRITICAL_SECTION lock;
    CONDITION_VARIABLE cond;
    int stop;
} ThreadPool;

void initThreadPool(ThreadPool *pool, int thread_count);
void enqueueThreadPool(ThreadPool *pool, void (*func)(void*), void *arg);
void shutdownThreadPool(ThreadPool *pool);

#endif
