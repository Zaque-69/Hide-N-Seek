import osproc, strutils

proc runShellCommand*(command: string): void = 
  let result = execCmd(command)
