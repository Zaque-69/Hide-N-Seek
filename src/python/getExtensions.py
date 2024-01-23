import os, sys, shutil
home = os.getcwd()

#keeping a variable for "Files" folder
os.chdir("json")
moveExtensionsJson = os.getcwd()

#Deleting those file if already exists
for file in os.listdir():
    if file == "extensions.txt" or file == "howMany.json" : os.remove(file)

os.chdir("..")
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

#deleting directories from list
for file in ext:
    if not "." in file : ext.remove(file)

for i in ext :
    if not "." in ext[count] : del ext[count]
    else : 
        ext[count] = str(ext[count]).replace(".", "")
        count += 1
ext[len(ext) - 1] = ext[len(ext) - 1].replace(".", "")
count = 0
ext = list(set(ext))

with open('extensions.txt', 'a') as f : 
    for i in ext : 
        f.write(ext[count] + '\n')
        count += 1

shutil.move("extensions.txt", moveExtensionsJson)

#after moving the extension file, we are counting many files 
#from each extension are in the current directory

param, listOFElements = 0, []
for i in range (0, len(ext)):
    for file in os.listdir():
        if ext[i] in file: param += 1
    listOFElements.append(param)
    param = 0

with open("howMany.json", "a") as f:
    f.write("{ \n")
    for i in range(0, len(ext)) : 
        f.write(4 * ' ' + f'"{ext[i]}" : "{listOFElements[i]}"')
        if i + 1 < len(ext) : f.write(", \n")
    f.write("\n }")

shutil.move("howMany.json", moveExtensionsJson)
