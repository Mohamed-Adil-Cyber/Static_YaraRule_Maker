import pefile
from datetime import date
import sys
import re
import string
from string import ascii_lowercase


# import all components from the tkinter library
from tkinter import *

# used to make the icon file temporary
import tempfile
  
# import filedialog module
from tkinter import filedialog

# to Compress Image Icon
import base64, zlib

import argparse
import math



def shannon_entropy(data):
    # 256 different possible values
    possible = dict(((chr(x), 0) for x in range(0, 256)))

    for byte in data:
        possible[chr(byte)] +=1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in possible:
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy

# browsed file
filename = ''

# nop inside an exe
empty_Space = 0



# icon image as base64
ICON = zlib.decompress(base64.b64decode('eJxjYGAEQgEBBiDJwZDBy'
    'sAgxsDAoAHEQCEGBQaIOAg4sDIgACMUj4JRMApGwQgF/ykEAFXxQRc='))

# creating the icon image 
_, ICON_PATH = tempfile.mkstemp()
with open(ICON_PATH, 'wb') as icon_file:
    icon_file.write(ICON)

def strings(filename, min=8):
    with open(filename, errors="ignore") as file:
        result = ""
        for character in file.read():
            if character in string.printable:
                result += character
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result
# Python program to find the SHA-1 message digest of a file

# importing the hashlib module
import hashlib

def hash_file(filename):
   """"This function returns the SHA-1 hash
   of the file passed into it"""

   # make a hash object
   h = hashlib.sha1()

   # open file for reading in binary mode
   with open(filename,'rb') as file:

       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)

   # return the hex representation of digest
   return h.hexdigest()




def getMD5(filename): 
  
    # initialize hash 
    md5 = hashlib.md5() 
  
    # open file for reading in binary mode 
    with open(filename,'rb') as file: 
  
        # loop till the end of the file 
        chunk = 0
        while chunk != b'': 
            # read only 1024 bytes at a time 
            chunk = file.read(1024) 
            md5.update(chunk) 
  
    # return md5 digest 
    return md5.hexdigest()


def sha256_hash(filename):
   h  = hashlib.sha256()
   with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           h.update(chunk)
   return h.hexdigest()


  
# function for opening the file explorer window
def browseFiles():
    global filename

    # select file types on browser
    filename = filedialog.askopenfilename(
                                          title = "Select a File",
                                          filetypes = (("EXE files","*.exe*"),
                                                       ("DLL files","*.dll*"),                                                       
                                                       ("all files","*.*")))
    
      
    # change label contents
    label_file_explorer.configure(text="File Opened: "+filename)

      
    # activate cave button
    if filename != "":
        button_Caves.configure(state="normal")
    

# function to find caves
def caves():
 global filename
 pe = pefile.PE(filename)
 exe = filename.split("/")[-1].split(".")[0]
 with open(filename, 'rb') as f:
        data = f.read()
        f.close
 message = hash_file(filename)
 print(exe)
 with open(exe.replace('-','').replace('/ ','').replace(' ','')+'.yar', 'w+') as file:
    file.write("import \"hash\""+'\n'
      +"import \"pe\""+'\n'
      +"import \"math\""+'\n'
      +"import \"hash\""+'\n'         
      +"rule "+exe.replace('-','').replace('/ ','').replace(' ','')+'\n'
      +"{\n"+
      ' meta:\n'+
      '   description=\"Rule to find '+exe+'\"\n'+
      '   author = \"Mohamed Adil\"\n'+
      '   date = '+date.today().strftime("%d%m%Y")+'\n\n\n'
      ' strings:\n'
      '  $a = {4d 5a} \n')
   
    counter1 = 0
    counter2  = 0
    counter3  = 0
    counter4  = 0

    
    for string_line in strings(filename):
                try:
                    if "This filename cannot be run in DOS mode" not in string_line:
                     if "MinGW" not in string_line:
                        if "_" not in string_line:
                            if "idata" not in string_line:
                                if "rsrc" not in string_line:
                                    if "CRT" not in string_line:
                                        if "rdata" not in string_line:
                                            if "requestedExecutionLevel" not in string_line:
                                                if "rtc" not in string_line:
                                                    if string_line.replace("\n","").replace(" ","") != "":
                                                        if string_line.isascii():
                                                            if "\n" not in string_line:
                                                                if len(string_line) > 150:
                                                                    string_line = string_line[0:150]
                                                                    file.write('  $'+ascii_lowercase[counter1]+ascii_lowercase[counter2]+ascii_lowercase[counter3]+ascii_lowercase[counter4]+' = \"'+string_line.replace("\"","\\\"").replace("\\","\\\\")+'\" \n')
                                                                    counter1 = counter1 +1
                                                                else:
                                                                    file.write('  $'+ascii_lowercase[counter1]+ascii_lowercase[counter2]+ascii_lowercase[counter3]+ascii_lowercase[counter4]+' = \"'+string_line.replace("\"","\\\"").replace("\\","\\\\")+'\" \n')
                                                                    counter1 = counter1 +1
                except:
                    try:
                        counter1 = 0
                        counter2 = counter2 + 1
                    except:
                        try:
                            counter2 = 0
                            counter3 = counter3 + 1
                        except:
                            try:
                                counter3 = 0
                                counter4 = counter4 + 1
                            except:
                                counter4 = 0


    file.write('  \n\n\n'
          '  condition:\n'
          '  (hash.md5(0,filesize)=="'+getMD5(filename)+
          '\") and  \n  (hash.sha1(0,filesize)==\"'+message+
          '\") and \n  (hash.sha256(0,filesize)=="'+sha256_hash(filename)+
          '\") \n   or ($a at 0) and any of them \n'
          "   and (uint32(uint32(0x3C)) == 0x00004550) \n"+
          "   and (pe.number_of_sections == "+str(pe.FILE_HEADER.NumberOfSections)+")\n"
          "   and (pe.timestamp == "+str(pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[0])+")\n"
          "   "+"")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
          for imp in entry.imports:
            file.write ('   and pe.imports("'+str(entry.dll).replace("b","").replace("'","").replace("_","")+'", "'+str(imp.name).replace("b'_","").replace("'","")+'")\n')

    if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
            file.write("   and (pe.machine == pe.MACHINE_I386)\n")
    elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
            file.write("   and (pe.machine == pe.MACHINE_AMD64)\n")
    counter = 0
    counter = 0
    for section in pe.sections:
        file.write('   and pe.sections['+str(counter)+'].name == "'+str(section.Name.decode()).replace("\0","")+'" \n')
        counter = counter + 1

    string_version_info = {}
    
    try:
        for fileinfo in pe.FileInfo[0]:
                if fileinfo.Key.decode() == 'StringFileInfo':
                        for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                        string_version_info[entry[0].decode()] = entry[1].decode()

        for i in string_version_info:
            file.write('   and pe.version_info["'+i + '"] contains "' + string_version_info[i]+ '" \n')
    except:
        pass
        
    if data:
            entropy = shannon_entropy(data)
            file.write("   and math.entropy(0, filesize) >= "+str(entropy).split(".")[0]+".0 \n")
    file.write('\n\n\n'+
          '}'
          )
    label_file_explorer.configure(text="DONE: "+ exe.replace('-','').replace('/ ','').replace(' ','') + ".yar created")
                                                                                                  
# create the root window
window = Tk()


window.iconbitmap(default=ICON_PATH)
  
# set window title
window.title('static yara rule writer')
  
# set window size
window.geometry("330x173")
  
# set window background color
window.config(background = "grey")
  
# create a File Explorer label
label_file_explorer = Label(window,
                            text = "Browse your EXE/DLL file",
                            width = 50, height = 3,
                            fg = "black")
  
# file explorer button size     
button_Explore = Button(window,
                        text = "Browse Files",
                        width = 30, height = 2,
                        command = browseFiles)
# exe cave button finder  
button_Caves = Button(window,
                     text = "Make a static yara rule",
                     state = DISABLED,
                     width = 30, height = 2,
                     command = caves)
# exit button size
button_Exit = Button(window,
                     text = "Exit",
                     width = 30, height = 2,
                     command = exit)
  
# grid method is chosen for placing the widgets at respective positions in a table like structure by specifying rows and columns
label_file_explorer.grid(column = 1, row = 1)

  
# file explorer button
button_Explore.grid(column = 1, row = 2)
  
# find code caves
button_Caves.grid(column = 1,row = 3)

# exit button
button_Exit.grid(column = 1,row = 4)
  
# let the window wait for any events
window.mainloop()
