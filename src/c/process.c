#include <stdio.h>
#include <dirent.h>
#include <string.h>

int main() {
    DIR *dir;
    FILE *file;

    struct dirent *ent;
    file = fopen("process.txt", "w");

    if ((dir = opendir("/proc")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type) {
                char path[255];
                snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
                FILE *cmdline_file = fopen(path, "r");
                if (cmdline_file != NULL) {
                    char cmdline[255];
                    if (fgets(cmdline, sizeof(cmdline), cmdline_file) != NULL) {
                        fprintf(file, "%s\n", cmdline);
                    }
                    fclose(cmdline_file);
                }
            }
        }
        closedir(dir);
        fclose(file);
    } else {
        perror("Error opening /proc directory");
        return 1;
    }
    return 0;
}
