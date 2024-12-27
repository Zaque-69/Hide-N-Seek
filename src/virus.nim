import 
    os

from ./malware/trojan/dropper import scanFilesDropperTrojan
from ./malware/cryptojacking/miner import scanFilesMiner

proc main() : void = 
    let argument : string = paramStr(1) 
    scanFilesDropperTrojan(argument)
    scanFilesMiner(argument)
   
when isMainModule : 
    main()