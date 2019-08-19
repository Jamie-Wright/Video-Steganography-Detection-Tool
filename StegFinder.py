import os
import binascii
import string
import re
import unicodedata
from os import listdir
from os.path import isfile, join

#Array containing all signatures
signatures = ["FBEAD881250FF9", "9E97BA2A008088C9A370975BA2E499B8C178720F88DDDC342B4E7D317FB5E87039A8B84275687191", "9E8DDB5073C2BF65B81E03AED562C6CC719AB9B94849D264EE49B7637BEFEBA10104407BF0ED2D8647E15FFC7C41C98BC902CA1C0721EE8D3266477C8FE14EE8AE66AB32E3D2F9A10E" "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]

def signature_detection(filename, file_directory, signatures):
    #Open Video file and read contents
    with open(file_directory + filename, "rb") as vf:
        videocontent = vf.read()

    #Parse Video file contents into hex on a single line for later tests
    outputstring = binascii.hexlify(videocontent)
    outputstring = outputstring.decode("utf-8")
    outputstring = outputstring.replace('\n', '')
    outputstring = outputstring.upper()
    
    #Test if the video file contents contains any of the signatures within the stored signatures
    for sig in signatures:
        if sig in outputstring:
            print(filename + ': Signature Found: ' + signature_type(sig))
            if signature_type(sig) == 'OurSecret':
                OurSecret_pw_replacement(filename, file_directory)
        else:
            print(filename + ': No Signature Found')

def signature_type(sig):
    #Dictionary to convert signature into corresponding steganography tool
    return {
        'FBEAD881250FF9' : 'DataHider' ,
        '9E97BA2A008088C9A370975BA2E499B8C178720F88DDDC342B4E7D317FB5E87039A8B84275687191' : 'OurSecret' ,
        '''9E8DDB5073C2BF65B81E03AED562C6CC719AB9B94849D264EE49B7637BEFEBA1
        0104407BF0ED2D8647E15FFC7C41C98BC902CA1C0721EE8D3266477C8FE14EE8AE66AB32E3D2F9A10E''' : 'Masker' ,
        '0000000000000000000000000000000000000000000000000000000000000000000000000' : 'OmniHide'
    }[sig]

def EOF_detection(filename, directory_path):
    #cmd command to run mp4dump analysis on mp4file
    command = "mp4dump.exe " + directory_path + filename + " > EOFresult.txt"
    os.system(command)

    #Search output file ReadAtom value for result indicating EOF
    with open("EOFresult.txt") as myfile:
        contents = myfile.read()
        if 'invalid atom size, extends outside parent atom' in contents:
            print('EOF Injection Discovered: ' + filename)
            signature_detection(filename, directory_path, signatures)
        else:
            print('No EOF Injection Discovered: ' + filename)

def MP4_MetaData(filename, directory_path):
    #cmd command to run mp4dump analysis on mp4file
    command = "mp4dump.exe " + directory_path + filename + " > Flagresult.txt"
    os.system(command)

    #Read the output file
    contents = open("Flagresult.txt", "r")
    Num_Positive_Flags, Num_Negative_Flags = 0, 0
    Flags = []
    
    #extract the lines containing flag information
    for line in contents:
        if "flags =" in line:
            Flags.append(line)
    for flag in Flags:
        #search if the flag is negative, add result to relevant counter
        if "0x00000" in flag:
            Num_Negative_Flags += 1
        else:
            Num_Positive_Flags += 1
    #compare the number of null flags to positive, print the relevant result
    if Num_Negative_Flags < Num_Positive_Flags:
        print("""File is likely to contain content hidden by OpenPuff.
         Positive flags: """+str(Num_Positive_Flags)+
         " Negative flags: "+str(Num_Negative_Flags)+
         " Filename: "+filename)
    else:
        print("""File is unlikely to contain content hidden by OpenPuff.
         Positive flags: """+str(Num_Positive_Flags)+
         " Negative flags: "+str(Num_Negative_Flags)+
         " Filename: "+filename)

def OurSecret_pw_replacement(filename, directory_path):
    with open(directory_path, filename, 'r+b') as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(size - 20)
        file.write(b'\x6C\x3C\x39\x6C\x30\x6B\x6C\x31\x30\x6E\x38\x38\x6A\x3A\x38\x3C')

def extract_filesize(file_directory, filename):

        #open file and read data
        with open(file_directory + filename, "rb") as vf:
                videocontent = vf.read()

        #parse output into searchable format
        outputstring = binascii.hexlify(videocontent)
        outputstring = outputstring.decode("utf-8")
        outputstring = outputstring.replace('\n', '')
        outputstring = outputstring.upper()

        #extract section containing file size information
        file_end_location = len(outputstring)
        data = outputstring[(file_end_location-50):(file_end_location)]
        data = data.lower()
        data = data.strip()

        #convert hex data into ASCII and remove all non printable characters
        result = ''.join(chr(int(data[i:i+2], 16)) for i in range(0, len(data), 2))
        result = re.sub(f'[^{re.escape(string.printable)}]', '.', result)

        #Match pattern of numbers 2 or more in length
        match = re.compile(r"[\d]{2,}").findall(result)

        #calculate original file size using information extracted
        full_file_size = os.stat(file_directory + filename).st_size 
        original_file_size = int(match[len(match) -1])
        injected_file_size = full_file_size - original_file_size

        #Print results in KB
        print("Injected file size: " + str(int(injected_file_size/1000)) + "KB")

def extract_filename(file_directory, filename, signature):
    #open file and read data
    with open(file_directory + filename, "rb") as vf:
        videocontent = vf.read()

    #parse output into searchable format
    outputstring = binascii.hexlify(videocontent)
    outputstring = outputstring.decode("utf-8")
    outputstring = outputstring.replace('\n', '')
    outputstring = outputstring.upper()

    #Search for signature which denotes the start of injection
    result = outputstring.find(signature)

    #cut 256 characters (512 hex characters) which is the max length a filename can be
    data = outputstring[(result-512):(result)]
    data = data.lower()
    data = data.strip()

    #convert hex into Ascii and remove non printable characters
    result = ''.join(chr(int(data[i:i+2], 16)) for i in range(0, len(data), 2))
    result = re.sub(f'[^{re.escape(string.printable)}]', '.', result)

    #match all filename-like patterns into an array, then print last match
    match = re.compile(r"[\w\d\s-]*\.[A-Za-z]{2,}").findall(result)
    print(match[len(match) -1])

def main():
    print("Start")
    directory_path = ""
    files = [f for f in listdir(directory_path) if isfile(join(directory_path, f))]
    for filename in files:
        EOF_detection(filename, directory_path)
        MP4_MetaData(filename, directory_path)
    
if __name__== "__main__":
    main()

print("End")