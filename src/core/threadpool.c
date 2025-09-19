#include <../include/threadpool.h>

#define MAX_QUEUE_SIZE 100 // Giới hạn kích thước hàng đợi

Task *task_head = NULL, *task_tail = NULL;

volatile int stop_thread_pool = 0; // biến truy cập ngoài luồng

CRITICAL_SECTION queue_lock;
HANDLE task_sema; //handle tuong tac voi semaphore
static int current_queue_size = 0; // Biến đếm số lượng task trong hàng đợi

void init_thread_pool(int n) {
    log_message("INFO", "Initializing thread pool");
    InitializeCriticalSection(&queue_lock);
    task_sema = CreateSemaphore(NULL, 0 ,0x7fffffff, NULL);

    for (int i =0; i < n; i++) {
        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, work_thread, NULL, 0, NULL);
        if (h == 0) {
            log_message("ERROR", "Failed to create thread");
            printf("Failed to create thread\n");
            exit(EXIT_FAILURE);
        }
        log_message("INFO", "Created a worker thread");
        CloseHandle(h);
    }
    log_message("INFO", "Thread pool initialized");
}

unsigned _stdcall work_thread(void *arg) {
    (void)arg; // unused
    log_message("INFO", "Worker thread started");
    while (1) {
        WaitForSingleObject(task_sema,INFINITE); // cho den khi co task
        
        if (stop_thread_pool) {
            log_message("INFO", "Worker thread stopping due to shutdown signal");
            break;
        }

        EnterCriticalSection(&queue_lock);
            Task *t = dequeue_task();
        LeaveCriticalSection(&queue_lock);

        if(t) {
            log_message("INFO", "Worker thread executing a task");
            t->function(t->arg);
            free(t);
            log_message("INFO", "Worker thread finished executing a task");
        } else {
            log_message("WARN", "Worker thread woke up but no task found");
        }
    }
    log_message("INFO", "Worker thread exited");
    return 0;
}

void enqueue_task(void (*function)(void*), void *arg) {
    log_message("INFO", "Enqueueing a new task");
    // Kiểm tra nếu hàng đợi đã đầy
    EnterCriticalSection(&queue_lock);
    if (current_queue_size >= MAX_QUEUE_SIZE) {
        log_message("ERROR", "Task queue is full, rejecting task");
        printf("Task queue is full, rejecting task\n");
        LeaveCriticalSection(&queue_lock);
        return;
    }
    LeaveCriticalSection(&queue_lock);

    // Tạo task mới
    Task *t = malloc(sizeof(Task));
    if (!t) {
        log_message("ERROR", "Failed to allocate memory for task");
        printf("Failed to allocate memory for task\n");
        return;
    }
    t->function = function;
    t->arg = arg;
    t->next = NULL;

    // Vao vung nho lock (chi 1)
    EnterCriticalSection(&queue_lock);
    if (task_tail == NULL) {
        task_head = task_tail = t;
    } else {
        task_tail->next = t;
        task_tail = t;
    }
    current_queue_size++; // Tăng biến đếm số lượng task
    LeaveCriticalSection(&queue_lock);

    log_message("INFO", "Task enqueued successfully");

    // Báo tin cho worker
    ReleaseSemaphore(task_sema, 1, NULL);
}

Task* dequeue_task() {
    Task *t = NULL;
    // Đã lock ở caller
    if (task_head) {
        t = task_head;
        task_head = t->next;
        if (!task_head) { // head null thi gan tail null
            task_tail = NULL;
        }
        current_queue_size--; // Giảm biến đếm số lượng task
    }
    return t;
}

void shutdown_thread_pool() {
    log_message("INFO", "Shutting down thread pool");
    stop_thread_pool = 1;
    ReleaseSemaphore(task_sema, 100, NULL); // Đánh thức tất cả thread
    Sleep(100); // Chờ thread kết thúc
    DeleteCriticalSection(&queue_lock);
    CloseHandle(task_sema);
    log_message("INFO", "Thread pool shutdown complete");
}
