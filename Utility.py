from enum import Enum
from re import finditer

class COLORS(Enum):
	RED="\033[31m"
	GREEN="\033[32m"
	BLUE="\033[34m"
	WHITE="\033[37m"

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
        debug("%s <--> %s"%(toMatchLower,startLower))
        if toMatchLower.startswith(startLower):
            debug()
            return start
    debug()
    #this is implicit and doesn't need to be added
    return None
    
