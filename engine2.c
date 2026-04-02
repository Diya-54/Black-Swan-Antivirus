#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <yara.h>
#include <sys/stat.h>

#define PATH_SEPARATOR '/'
#define BUFFER_SIZE 1024
#define MAX_MATCHES 100

typedef struct {
    char* matches[MAX_MATCHES];
    int count;
} MatchList;

int scanCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    MatchList* matchList = (MatchList*)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*)message_data;
        if (matchList->count < MAX_MATCHES) {
            matchList->matches[matchList->count] = strdup(rule->identifier);  // Copy rule name
            matchList->count++;
        }
    }

    return CALLBACK_CONTINUE;
}

void scanFile(const char* filePath, YR_RULES* rules, MatchList* matchList) {
    yr_rules_scan_file(rules, filePath, SCAN_FLAGS_REPORT_RULES_MATCHING, scanCallback, matchList, 0);
}

void scanDirectoryRecursively(const char* dirPath, YR_RULES* rules, MatchList* matchList) {
    DIR* dir = opendir(dirPath);
    if (!dir) {
        perror("[-] Failed to open directory");
        return;
    }

    struct dirent* entry;
    char path[BUFFER_SIZE];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dirPath, entry->d_name);

        struct stat path_stat;
        stat(path, &path_stat);

        if (S_ISDIR(path_stat.st_mode)) {
            scanDirectoryRecursively(path, rules, matchList);  // Recurse
        } else if (S_ISREG(path_stat.st_mode)) {
            scanFile(path, rules, matchList);
        }
    }

    closedir(dir);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file-or-directory-to-scan>\n", argv[0]);
        return 1;
    }

    const char* rules_dir = "/home/diya/antivirusproject/Black-Swan/myrule/compiled/";
    const char* target_path = argv[1];

    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[-] Failed to initialize YARA\n");
        return 1;
    }

    DIR* dir = opendir(rules_dir);
    if (!dir) {
        perror("[-] Failed to open compiled rules directory");
        yr_finalize();
        return 1;
    }

    struct dirent* entry;
    struct stat path_stat;
    stat(target_path, &path_stat);

    printf("[+] Scanning: %s\n", target_path);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yarac") != NULL) {
            char rule_file[BUFFER_SIZE];
            snprintf(rule_file, sizeof(rule_file), "%s/%s", rules_dir, entry->d_name);

            YR_RULES* rules = NULL;
            if (yr_rules_load(rule_file, &rules) == ERROR_SUCCESS) {
                MatchList matchList = {.count = 0};

                if (S_ISREG(path_stat.st_mode))
                    scanFile(target_path, rules, &matchList);
                else if (S_ISDIR(path_stat.st_mode))
                    scanDirectoryRecursively(target_path, rules, &matchList);
                else
                    printf("[-] Unknown target type.\n");

                if (matchList.count > 0) {
                    for (int i = 0; i < matchList.count; ++i) {
                        printf("✅ Matched rule: %s\n", matchList.matches[i]);
                        free(matchList.matches[i]);
                    }
                }

                yr_rules_destroy(rules);
            } else {
                fprintf(stderr, "[-] Failed to load compiled rules: %s\n", rule_file);
            }
        }
    }

    closedir(dir);
    yr_finalize();

    return 0;
}
