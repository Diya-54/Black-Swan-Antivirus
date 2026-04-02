#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <sys/wait.h>
#include <dirent.h> //S15
#include <sys/stat.h> //S15
#include <stdbool.h> //S15
char exceptions[50][PATH_MAX]; int exCount = 0; //For exceptions S15

void LoadExceptions() { //S15
    FILE* f = fopen("exceptions.txt", "r");
    if (!f) return;
    while (fgets(exceptions[exCount], PATH_MAX, f) && exCount < 50) {
        exceptions[exCount][strcspn(exceptions[exCount], "\n")] = 0;
        exCount++;
    }
    fclose(f);
}

bool IsExcluded(const char* path) { //S15
    char absPath[PATH_MAX];
    realpath(path, absPath);  // normalize to absolute path if possible

    for (int i = 0; i < exCount; i++) {
        if (exceptions[i][0] == '\0') continue;

        // Normalize exclusion path (remove trailing slash)
        char exNorm[PATH_MAX];
        strncpy(exNorm, exceptions[i], PATH_MAX - 1);
        exNorm[PATH_MAX - 1] = '\0';
        size_t len = strlen(exNorm);
        if (len > 0 && exNorm[len - 1] == '/')
            exNorm[len - 1] = '\0';

        // Convert exclusion path to absolute path as well
        char exAbs[PATH_MAX];
        if (realpath(exNorm, exAbs) == NULL)
            strncpy(exAbs, exNorm, PATH_MAX - 1);

        // Now check if 'path' begins with the exclusion directory
        if (strncmp(absPath, exAbs, strlen(exAbs)) == 0)
            return true;
    }
    return false;
}


#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + NAME_MAX + 1))

struct ScanArgs { //S15
    char filePath[PATH_MAX];
};

void* ScanThread(void* arg) {
    struct ScanArgs* data = (struct ScanArgs*)arg;

    pid_t pid = fork();
    if (pid == 0) {  // child process
        execl("/home/diya/antivirusproject/Black-Swan/engine", 
        "./engine", data->filePath, (char *)NULL);
        perror("execl failed");
        exit(1);
    } else if (pid < 0) {
        perror("fork failed");
    } else {
        wait(NULL);  // parent waits for this scan's child
    }

    free(data);
    return NULL;
} //S15

void CallDetectionEngine(const char* filePath) { //S15
if (IsExcluded(filePath)) return;   // for CallDetectionEngine

    printf("[+] Called detection for: %s\n", filePath);
    fflush(stdout);

    pthread_t scanThread;
    struct ScanArgs* args = malloc(sizeof(struct ScanArgs));
    strncpy(args->filePath, filePath, PATH_MAX - 1);
    args->filePath[PATH_MAX - 1] = '\0';

    if (pthread_create(&scanThread, NULL, ScanThread, args) != 0) {
        perror("pthread_create for ScanThread");
        free(args);
        return;
    }

    pthread_detach(scanThread); // don't block main RTM
}//S15

void AddWatchRecursively(int fd, const char* basePath) { //S15
if (IsExcluded(basePath)) return;   // for AddWatchRecursively

    int wd = inotify_add_watch(fd, basePath, IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE);
    if (wd < 0) {
        fprintf(stderr, "[-] Failed to watch: %s -> %s\n", basePath, strerror(errno));
        return;
    }

    DIR* dir = opendir(basePath);
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", basePath, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
    if (!IsExcluded(path))          // skip excluded folders - S15.2
        AddWatchRecursively(fd, path); // recursive call for subfolder
}

    }

    closedir(dir);
}//S15

void* MonitorDirectoryThread(void* arg) { //S15
    char* directoryPath = (char*)arg;
if (IsExcluded(directoryPath)) {    // skip excluded directories entirely  S15.3
    printf("[-] Skipping excluded root directory: %s\n", directoryPath);
    free(directoryPath);
    return NULL;
}

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        free(directoryPath);
        return NULL;
    }

    // Add recursive watch on base directory and its subdirectories
    AddWatchRecursively(fd, directoryPath);

    printf("[+] Monitoring directory (recursive): %s\n", directoryPath);
    fflush(stdout);

    char buffer[BUF_LEN];
    while (1) {
        ssize_t length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }

        ssize_t i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                char fullPath[PATH_MAX];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", directoryPath, event->name);
                if (IsExcluded(fullPath)) {
    			i += EVENT_SIZE + event->len;
    			continue;
			}
                printf("[+] Change detected in file: %s\n", fullPath);
		
                struct stat st;
                if (stat(fullPath, &st) == 0 && S_ISDIR(st.st_mode)) {
                    printf("[+] New directory detected, adding watch: %s\n", fullPath);
                    AddWatchRecursively(fd, fullPath);
                }

                fflush(stdout);
if (!IsExcluded(fullPath)) 
                CallDetectionEngine(fullPath);
            }
            i += EVENT_SIZE + event->len;
        }
    }

    close(fd);
    free(directoryPath);
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <directory1> [directory2] [...]\n", argv[0]);
        return 1;
    }
LoadExceptions(); //S15
printf("[+] %d exclusions loaded\n", exCount); //S15

    for (int i = 1; i < argc; i++) {


        pthread_t thread_id;
        char* dir = strdup(argv[i]);
        if (pthread_create(&thread_id, NULL, MonitorDirectoryThread, dir) != 0) {
            fprintf(stderr, "[-] Failed to create thread for: %s\n", argv[i]);
            free(dir);
        }
        pthread_detach(thread_id);  // detach thread to avoid memory leaks
    }

    printf("Press 'q' followed by Enter to exit...\n");
    char userInput;
    do {
        userInput = getchar();
    } while (userInput != 'q');

    return 0;
}
