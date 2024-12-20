#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>   // getopt() to parse command line arguments
#include <pthread.h>
#include <sched.h>

// Record the attributes of each thread
typedef struct {
    int id;
    int policy;
    int priority;
    double time_wait;
} thread_data_t;

pthread_barrier_t barrier;

void *thread_func(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    struct sched_param param;

    param.sched_priority = data->priority;
    pthread_setschedparam(pthread_self(), data->policy, &param);

    // Wait until all threads are ready
    pthread_barrier_wait(&barrier);

    // Do the task for 3 times
    for (int i = 0; i < 3; i++) {
        printf("Thread %d is starting\n", data->id);

        // Simulate busy waiting
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);    // Use CLOCK_MONOTONIC to avoid the influence of variation of system time.
        do {    // Use a post-test loop to start timing immediately, rather than waiting until after the conditional checks.
            clock_gettime(CLOCK_MONOTONIC, &end);
        } while ((end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 < data->time_wait);    // Align unit to second
    }

    pthread_exit(NULL);    // Exit the function
}

int main(int argc, char *argv[]) {
    // Initialization
    int num_threads = 0;
    double time_wait = 0.0;
    int *policies = NULL;
    int *priorities = NULL;
    int opt;

    // Parse program arguments
    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
            case 'n':
                num_threads = atoi(optarg);
                break;
            case 't':
                time_wait = atof(optarg);
                break;
            case 's': {
                policies = malloc(num_threads * sizeof(int));
                char *token = strtok(optarg, ",");
                for (int i = 0; i < num_threads && token != NULL; i++) {
                    policies[i] = (strcmp(token, "FIFO") == 0) ? SCHED_FIFO : SCHED_OTHER;
                    token = strtok(NULL, ",");    // Go to the next token
                }
                break;
            }
            case 'p': {
                priorities = malloc(num_threads * sizeof(int));
                char *token = strtok(optarg, ",");
                for (int i = 0; i < num_threads && token != NULL; i++) {
                    priorities[i] = atoi(token);
                    token = strtok(NULL, ",");
                }
                break;
            }
            default:    // If the arguments format is wrong.
                fprintf(stderr, "Usage of %s: -n <num_threads> -t <time_wait> -s <policies> -p <priorities>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (num_threads <= 0 || policies == NULL || priorities == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        return -1;
    }

    pthread_t threads[num_threads];
    thread_data_t thread_data[num_threads];

    pthread_barrier_init(&barrier, NULL, num_threads);    // Initialize the barrier

    // Set the CPU affinity of all threads to the same CPU（such as CPU 0）
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);  // Set to CPU 0
    
    // Initialization of thread attributes then set CPU affinity
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
    
    // Create worker threads
    for (int i = 0; i < num_threads; i++) {
        // Assign thread properties
        thread_data[i].id = i;
        thread_data[i].policy = policies[i];
        thread_data[i].priority = (policies[i] == SCHED_FIFO) ? priorities[i] : 0;
        thread_data[i].time_wait = time_wait;

        // Set thread attributes
        pthread_attr_setschedpolicy(&attr, policies[i]);
        struct sched_param param;
        param.sched_priority = thread_data[i].priority;
        pthread_attr_setschedparam(&attr, &param);

        // Create threads
        pthread_create(&threads[i], &attr, thread_func, (void *)&thread_data[i]);
    }
    
    pthread_attr_destroy(&attr);

    // Wait for all the threads being done
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Free all the allocation
    pthread_barrier_destroy(&barrier);
    free(policies);
    free(priorities);

    return 0;
}
