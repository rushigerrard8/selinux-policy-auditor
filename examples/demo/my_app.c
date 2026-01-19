/*
 * my_app - Demo application for SELinux Prober
 *
 * This application only READS from /var/log directory,
 * but the SELinux policy grants excessive write permissions.
 *
 * Use SELinux Prober to identify the unused permissions!
 */

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int count = 0;
    int iteration = 0;

    printf("========================================================\n");
    printf("my_app: Demo Application Starting\n");
    printf("========================================================\n");
    printf("Purpose: Read files from /var/log directory\n");
    printf("SELinux Context: my_app_t\n");
    printf("Running continuously (Ctrl+C to stop)\n");
    printf("========================================================\n\n");

    // Run forever, scanning every 10 seconds
    while (1) {
        iteration++;
        printf("\n[Iteration %d - %s]\n", iteration,
               iteration == 1 ? "First scan" : "Periodic scan");

        // Open /var/log directory
        printf("[1] Opening /var/log directory...\n");
        dir = opendir("/var/log");
        if (dir == NULL) {
            fprintf(stderr, "ERROR: Failed to open /var/log: %s\n", strerror(errno));
            sleep(10);
            continue;
        }
        printf("    - Successfully opened /var/log\n");

        // Read directory contents
        printf("[2] Reading directory contents and probing metadata...\n");
        count = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char path[512];
            snprintf(path, sizeof(path), "/var/log/%s", entry->d_name);

            // Probing metadata with different system calls
            // Each of these triggers different SELinux checks

            // stat() triggers getattr
            if (stat(path, &st) == 0) {
                // lstat() triggers getattr
                lstat(path, &st);

                // access() triggers getattr + read/write check
                access(path, R_OK);

                if (count < 5) { // Only print first 5
                    printf("    - %s ", entry->d_name);
                    if (S_ISDIR(st.st_mode)) {
                        printf("(directory)\n");
                    } else if (S_ISREG(st.st_mode)) {
                        printf("(file, %ld bytes)\n", st.st_size);
                    } else {
                        printf("(other)\n");
                    }
                }
            }
            count++;
        }
        closedir(dir);
        printf("    - Probed metadata for %d total entries\n", count);

        // Try to read multiple log files
        printf("[3] Reading multiple log files...\n");
        const char *log_files[] = {
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/cron",
            "/var/log/maillog",
            "/var/log/boot.log",
            "/var/log/dmesg",
            "/var/log/audit/audit.log",
            "/var/log/yum.log",
            "/var/log/spooler",
            "/var/log/tuned/tuned.log",
            NULL
        };

        int files_read = 0;
        for (int i = 0; log_files[i] != NULL; i++) {
            // Open read-only
            int fd = open(log_files[i], O_RDONLY);
            if (fd >= 0) {
                char buf[1024];
                // Read a chunk
                ssize_t bytes = read(fd, buf, sizeof(buf));
                close(fd);
                printf("    - %s (%ld bytes read)\n", log_files[i], (long)bytes);
                files_read++;
            }
        }
        printf("    - Successfully read %d log files\n", files_read);

        printf("\n>> Scan complete. Sleeping 10 seconds...\n");
        printf("   (Press Ctrl+C to stop)\n");

        sleep(10);
    }

    return 0;
}
