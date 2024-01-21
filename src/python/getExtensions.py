import os,sys
home = os.getcwd()
os.chdir(str(sys.argv[1]))
ext, string = [], ""
ok = 1
for i in os.listdir() : 
    for j in str(i)[::-1]: 
        if ok == 1 : string += j
        if str(j) == "." : ok = 0
    ext.append(string[::-1])
    string = ""
    ok = 1
count = 0
for i in ext :
    if not "." in ext[count] : del ext[count]
    else : 
        ext[count] = str(ext[count]).replace(".", "")
        count += 1
ext[len(ext) - 1] = ext[len(ext) - 1].replace(".", "")
count = 0
ext = list(set(ext))
with open('aux.txt', 'a') as f : 
    for i in ext : 
        f.write(ext[count] + '\n')
        count += 1
