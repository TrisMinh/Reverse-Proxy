#include "threadpool.h"
#include <stdlib.h>
#include <stdio.h>

static unsigned __stdcall worker_thread(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    Task task;

    while (1) {
        EnterCriticalSection(&pool->lock);
        while (pool->task_count == 0 && !pool->stop)
            SleepConditionVariableCS(&pool->cond, &pool->lock, INFINITE);

        if (pool->stop && pool->task_count == 0) {
            LeaveCriticalSection(&pool->lock);
            break;
        }

        task = pool->tasks[pool->head];
        pool->head = (pool->head + 1) % MAX_TASKS;
        pool->task_count--;
        LeaveCriticalSection(&pool->lock);

        task.func(task.arg);
    }

    return 0;
}

void initThreadPool(ThreadPool *pool, int thread_count) {
    InitializeCriticalSection(&pool->lock);
    InitializeConditionVariable(&pool->cond);
    pool->head = pool->tail = pool->task_count = 0;
    pool->stop = 0;
    pool->thread_count = thread_count;

    for (int i=0;i<thread_count;i++)
        pool->threads[i] = (HANDLE)_beginthreadex(NULL,0,worker_thread,pool,0,NULL);
}

void enqueueThreadPool(ThreadPool *pool, void (*func)(void*), void *arg) {
    EnterCriticalSection(&pool->lock);
    if (pool->task_count == MAX_TASKS) {
        LeaveCriticalSection(&pool->lock);
        printf("Task queue full!\n");
        return;
    }
    pool->tasks[pool->tail].func = func;
    pool->tasks[pool->tail].arg = arg;
    pool->tail = (pool->tail + 1) % MAX_TASKS;
    pool->task_count++;
    WakeConditionVariable(&pool->cond);
    LeaveCriticalSection(&pool->lock);
}

void shutdownThreadPool(ThreadPool *pool) {
    EnterCriticalSection(&pool->lock);
    pool->stop = 1;
    WakeAllConditionVariable(&pool->cond);
    LeaveCriticalSection(&pool->lock);

    WaitForMultipleObjects(pool->thread_count, pool->threads, TRUE, INFINITE);
    for (int i=0;i<pool->thread_count;i++)
        CloseHandle(pool->threads[i]);

    DeleteCriticalSection(&pool->lock);
}
