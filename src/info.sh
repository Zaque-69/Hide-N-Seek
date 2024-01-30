echo """
Usage: hidenseek [OPTION]... [FILE] / [PATH]
File manager and malware detector.

With no FILE / PATH, or when FILE / PATH is -, read standard input.

-A, --show-all           [PATh] Shows if a file from a path have 
                            an extension changed by checking its hex 
                            decimal header.

Examples:
nim c -r hidenSeek.nim -A /home/{username}/Desktop
#The output is only when a suspicious file is found.

Full documentation <https://github.com/Zaque-69/Hide-N-Seek>
"""
