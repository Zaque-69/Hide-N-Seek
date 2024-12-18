echo """
Hide 'N Seek - Z4que 2024 All rights reserved
Usage: ./hidenseek [OPTION]... [FILE] / [PATH]
File manager and malware detector.

-e (extensions) [PATH] Shows if a file from a path have 
                an extension changed by checking its hex decimal header.
                ex : ./hidenseek -e /home/{user}/Desktop/path

-m (malware)    [PATH] / [FILE] Shows if a file or some files 
                from a directory have malicious bytes using YARA rules.
                    
ex : ./hidenseek -m /home/{user}/Desktop/downloaded_dir

The malware scanned for this software : 
    https://github.com/Endermanch/MalwareDatabase
    https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main
    https://github.com/timb-machine/linux-malware
"""