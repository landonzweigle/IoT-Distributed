import os, sys
from enum import Enum
from re import finditer

class COLORS(Enum):
    RED="\033[31m"
    GREEN="\033[32m"
    BLUE="\033[34m"
    WHITE="\033[37m"
    BLACK="\u001b[38;5;16m"
    ORANGE="\u001b[38;5;178m"

def debug(msg="", color=None):
    if(color != None and not isinstance(color, COLORS)):
        raise Exception("Debug expected color but %s was given."%type(color))
    else:
        if(color!=None):
            color=color.value
            end="\033[0m"
        else:
            color=""
            end=""
    print("%s%s%s"%(color,msg,end))

# def dict_to_stir()


def camel_case_split(identifier):
    matches = finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    return [m.group(0) for m in matches]

def inLower(string, arr):
    lower = string.lower()

    for toMatch in arr:
        print("%s vs %s"%(string,toMatch))
        if(lower==toMatch.lower()):
            return True
    return False
    
def starts_with_any(toMatch, startwithArr):
    toMatchLower = toMatch.lower()
    for start in startwithArr:
        startLower = start.lower()
        if toMatchLower.startswith(startLower):
            debug("%s <--> %s"%(toMatchLower,startLower),COLORS.GREEN)
            debug()
            return start
        else:
            debug("%s <--> %s"%(toMatchLower,startLower),COLORS.RED)


    debug()
    #this is implicit and doesn't need to be added
    return None
    
def raise_filePath_DNE(file):
    if(isinstance(file,str)==False and not file):
        raise Exception("Argument:'file' is not a valid string.")

    fileSPLT = file.split('/')
    splitLen = len(fileSPLT)

    if(splitLen==1):
        return "./%s"%(file)
    elif(splitLen>1):
        fileName = fileSPLT[-1]
        filePath = "/".join(fileSPLT[:-1])
        if(os.path.isdir(filePath)==False):
            raise Exception("File path is not valid.")
        else:
            return file

#returns name appended to path where name is non-colliding (if file path+name+name.extension exists, return path+name(n)+name.extension where n is the first unique path)
#path is optional. if not provided return will be CWD+name(n)
#path must be a valid directory
def get_unique_filename(name, path='.'):
    if(isinstance(name,str)==False and not name):
        raise Exception("Argument:'name' must be a valid (non empty) string.")

    if(os.path.isdir(path)==False):
        raise Exception("Argument:'path' %s is not a valid path. When creating a unique file, the path must exist."%path)

    nameSPLT = name.split('.')
    if(len(nameSPLT)>1):
        nameExtension="."+nameSPLT[-1]
        nameRoot=nameSPLT[0]
    else:
        raise Exception("Argument:'name' (provided '%s') must be of the form [*valid os-file characters*].[a-zA-Z]"%name)

    baseName = os.path.normpath("%s/%s"%(path,nameRoot))
    newPath = baseName + nameExtension

    tried=0
    while(os.path.isfile(newPath)):
        debug("...Path %s exists."%newPath,COLORS.RED)
        tried+=1
        newPath="%s(%d)%s" % (baseName,tried,nameExtension)
        debug("\tTrying new path %s" % newPath,COLORS.RED)


    debug("\nexp dir is %s" % newPath, COLORS.GREEN)
    # os.mkdir(newPath)
    return newPath