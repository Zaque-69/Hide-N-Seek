import osproc

proc runShellCommand * ( command : string ) : void = 
    # Running a shell comand
    
    discard execCmd(command)