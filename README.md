<p align = "center">
  <img width="300" alt="webui" src="https://github.com/Zaque-69/Hide-N-Seek/blob/main/logo.png">
</p>

# Hide 'N Seek
Basically, "Hide 'N Seek" it's a program written in based on Nim language, which is a file manager and malware detector. For example, we can use "Hide 'N Seek" to sort the fiels from a directory in folders by their extensions or to see information about files and cheks if the files are malitious or not, thanks to personal Yara rules.


# Examples
```
./hidenseek.nim -a /home/{username}/Desktop
```

The above command checks if in the respective location there is a file with an extension changed. This command simply check the Hex Decimal header of the file with the extension. This works with any directory.

```
./hidenseek.nim -m /home/{username}/Desktop 
```
```
./hidenseek.nim -m /home/{username}/Desktop/file.exe
```

The above command checks if the directory or the file contains malware bytes, thanks to YARA personal rules. ( Checks for : Ransomware / Cryptography, BTC miner virus, etc. )

# Imports

```nim
import filelist
```

# Procs

```nim
proc createArray(size: int): seq[string] =
  return newSeq[string](size)

proc countRows(filename : string) : int = 
    for line in lines filename : count += 1
    return count 

proc fileList*( path : string ) : seq[string] =
    #witing the files from a path using C
    let runCommand : int = execCmd(fmt"clear && gcc main.c -o main && ./main {path}")

    #counting rows
    var rows : seq[string] = createArray(countRows("output.txt"))

    count = 0

    for line in lines "output.txt" : 
        rows[count] = line
        count += 1

    #deleting the first 2 rows that contain only dots
    delete(rows, 1)
    delete(rows, 0)

    let deleteTxt : int = execCmd("rm output.txt")

    return rows
```
# C code
```C
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
```
