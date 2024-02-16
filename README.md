<p align = "center">
  <img width="300" alt="webui" src="https://github.com/Zaque-69/Hide-N-Seek/blob/main/logo.png">
</p>

# Hide 'N Seek
Basically, "Hide 'N Seek" it's a program based on Nim, C and Yara languages, which is a file manager and malware detector. For example, we can use "Hide 'N Seek" to sort the fiels from a directory in folders by their extensions or to see information about files and cheks if the files are malitious or not, thanks to personal Yara rules.


# Commands

- checks if in the respective location there is a file with an extension changed. This command simply check the Hex Decimal header of the file with the extension. This works with any directory.

```
./hidenseek.nim -a /home/{username}/Desktop
```
- checks if the directory or the file contains malware bytes, thanks to YARA personal rules. ( Checks for : Ransomware / Cryptography, BTC miner virus, etc. )

```
./hidenseek.nim -m /home/{username}/Desktop 
```
```
./hidenseek.nim -m /home/{username}/Desktop/file.exe
```

-  scans the running files ( files from 'proc' directory in Linux );

```
./hidenseek.nim -p 
```
