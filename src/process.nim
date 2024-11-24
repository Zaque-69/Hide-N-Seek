import os
import std/strutils

proc open_process(process : string) : bool = 
    try : 
        if readFile(process & "/exe").len() > 1 : 
            return true
    except IOError: 
        return false

proc process_dir_list() : seq[string]= 
    #filtering the directories from "/proc" by numbers 
    var 
        proc_list : seq[string] = @[]
        check : bool = false

    for file in walkDir("/proc") : 
        if file.kind == pcDir :
            var dir : string = file.path 
            for i in 0..dir.len() - 1 : 
                if isDigit(dir[i]) : 
                    check = true
            
            if check : 
                if open_process(dir) : 
                    proc_list.add(dir)  
                         
            check = false

    return proc_list

echo process_dir_list()