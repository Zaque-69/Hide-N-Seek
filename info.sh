eye_ascii(){
    echo -e """\e[33m
                                    .**     
                                  .+%=      
                :=+#%%%###%%#*= .*%=        
            :+##@@#-.       -=.+%=.-        
         :+%+:.#*.          .+%=:-.=%*:     
       :#%-  .@+     =###:.*%=  :@-  :*%-   
     .#%-    *%    .@+  .+%=     +@    .*%: 
     %#      %+    *# .*%= =%    :@:     =@:
     .##.    ##    ..+%=  .%+    =@     +@= 
       -%*:  :@=  .+%=.**#*:    .@=  .+@+   
         :*%=.:=.*%=           -@= -#%=     
            ==.+%=::        .=%@*##+:       
            .*%= :#%@%#**##@%#*=:           
          .+%=                              
         =%=                                

  \e[37mHide 'N Seek - \e[35mZ4que 2024 All rights reserved
    """
}

help(){
    eye_ascii
    echo -e """\e[37m
Usage: ./hidenseek [OPTION]... [FILE] / [PATH]
File manager and malware detector.

With no FILE / PATH, or when FILE / PATH is -, read standard input.

\e[33m-a, --show-all              \e[37m[PATh] Shows if a file from a path have 
                            an extension changed by checking its hex 
                            decimal header.

\e[33mExamples:
\e[37m[PATh]nim c -r hidenSeek.nim -A /home/{username}/Desktop
#The output is only when a suspicious file is found.

Full documentation <https://github.com/Zaque-69/Hide-N-Seek>
"""

}
