#include <stdio.h>
#include <dirent.h>

int main(int argc, char *argv[]) {

    DIR *dir = opendir(argv[1]);
    FILE *outputFile = fopen("output.txt", "w");
    struct dirent *entry;


    if ( dir == NULL ) {
        perror("Error opening directory");
        return 1;
    }

    if ( outputFile == NULL ) {
        perror("Error opening output file");
        closedir(dir);
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        fprintf(outputFile, "%s\n", entry->d_name);
    }

    return 0;
}
