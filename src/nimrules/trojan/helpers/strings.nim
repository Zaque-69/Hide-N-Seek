import
    os,
    sets,
    sequtils,
    strformat,
    strutils

# Removing duplicate elemnts from a sequence 
proc removeDuplicates[T](s: seq[T]): seq[T] =
    let uniqueSet = toHashSet(s) 
    result = toSeq(uniqueSet) 

# Removing local IP's from the sequence
proc removeLocalIPs * (ips: seq[string]): seq[string] =
    var boolean : bool = true
    let localIPs = @["127.0", "33.0.0.0", "0.0.0.0", "8.8.8.8", "192.168", "10.0"]
    for ip in ips:
        for local in localIPs : 
            if contains(ip, local):  
                boolean = false
            
        if boolean : 
            add(result, ip)
        
        boolean = true

    result

# Appending text to a file. If the file doesn't exist, we create one
proc appendToFile * (filename: string, content: string) =
    if fileExists(filename):
        writeFile(filename, readFile(filename) & content)
    else:
        writeFile(filename, content)

proc suspiciousCommandsDroperTrojan * () : seq[string] = 
    @[
        "sh bins.sh",
        "&& chmod 777",
        "rm -rf bins.sh",
        "reeee/setup.sh;",
        "-c get tftp1.sh;",
        "chmod +x bins.sh",
        "rm -rf /tmp/*.history -c",
        "BootzIV.sh && ./BootzIV.sh",
        "ftpget -v -u anonymous -p anonymous -P",
        "rm -rf /var/log/wtmp.history -c;history -w",
        "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*",
        "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;"
    ]

proc suspiciousIPCombinationDroperTrojan * (ip : string) : seq[string] =
    @[
        ip,
        ip & ".telnet",
        ip & "/bins.sh",
        "wget+" & ip,
        "wget " & ip,
        "HOST: " & ip,
        "wget -g" & ip,
        "curl -O " & ip,
        "wget -g " & ip & "-l /tmp/kh -r /mips",
    ]

proc virusRaportTrojan * (
        filename : string, 
        virus_type : string, 
        filesize : int,
        suspicious_ips : seq[string], 
        suspicious_commands : seq[string],
        suspicious_strings : seq[string]
    ) : string = 

    var comment : string = fmt"[WARNING!] File {filename} may be {virus_type} :" & '\n' & fmt"In the file were found the following : " & '\n' & fmt"File size : {filesize / 1000}KB" & '\n'
    if len(suspicious_ips) > 0 : comment = comment & fmt"SUSPICIOUS IPs : {removeDuplicates(suspicious_ips)}" & '\n'
    if len(suspicious_commands) > 0 : comment = comment & fmt"SUSPICIOUS COMMANDS : {removeDuplicates(suspicious_commands)}" & '\n'
    if len(suspicious_strings) > 0 : comment = comment & fmt"SUSPICIOUS STRINGS : {removeDuplicates(suspicious_strings)}" & '\n'

    comment & '\n'