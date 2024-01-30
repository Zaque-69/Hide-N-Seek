"""
Sorting files by saving the them from a directory in a
list and make folders by their extensions. Then moving
the files to the folder with its extension name.

Z4que 2024 - All rights reserved

"""
import os, shutil, sys, time
tm = time.time()
path = sys.argv[1]
home = os.getcwd()
os.chdir(path)
initlist, extesionslist = [], []
for file in os.listdir(): initlist.append(file[::-1])
for f in initlist : 
    ext = ''
    for letter in f :
        if letter == '.' : break
        ext += str(letter)
    extesionslist.append(ext[::-1])
extesionslist = list(dict.fromkeys(extesionslist))
for i in extesionslist : 
    try : os.mkdir(f'{i}Files')
    except : pass 
for file in os.listdir():
    for i in extesionslist:
        extLen = len(i)
        if file[-extLen:] == i : shutil.move(file, f'{i}Files')
os.chdir(home)
print("Execution time :", time.time() - tm)