import sys, os, time, pprint, window
from Utility import *
import pandas as pds

CAPTURE_DIR="./Captures/"
PRETTY_PRINTER=pprint.PrettyPrinter(indent=4)

def get_captures(capDir):
    toRet=[]
    match=COLORS.GREEN
    miss=COLORS.RED

    if(not os.path.isdir(capDir)):
        raise Exception("Argument %s is not a valid directory..."%capDir)
    for f in os.listdir(capDir):
        fType=COLORS.WHITE

        if((not f.startswith("IGN_")) and f.endswith(".pcap")):
            toRet.append(f)
            fType=match
        else:
            fType=miss

        debug(f,fType)
    return toRet

def get_devies(files):
    #devicePrefixes is a set (no duplicates) which contains the prefixes for each device.
    devicePrefixes={"Awox","AmazonDot","AmazonEcho","AmazonShow","DLink","TPLink","Musaic","IView","IDevice","SmartThingsHub","Omna","Wemo"}
    
    #devices is a dict such that: key=*device_name*:value=*[files]*
    devices = {deviceName:[] for deviceName in devicePrefixes}

    for f in files:
        pref = starts_with_any(f, devicePrefixes)

        if(pref):
            devices[pref].append(f)
        else:
            debug(splits,COLORS.RED)
            
    PRETTY_PRINTER.pprint(devices)
    return devices

# def get_device_df()

def conglomerate_data(deviceDict):
    global CAPTURE_DIR
    congDF = pds.DataFrame()

    for i, dictItem in enumerate(deviceDict.items()):
        deviceName, files = dictItem
        filesTrue = [os.path.normpath(CAPTURE_DIR + "/" + f) for f in files]
        print(filesTrue)
        print("%i: %s: %s" % (i, deviceName, filesTrue))
        dfIn = window.from_many(filesTrue)
        dfIn["Device"] = [deviceName] * len(dfIn)
        dfIn.index = [i] * len(dfIn)
        # print(dfIn)
        congDF = congDF.append(dfIn)
    return congDF
        

def main(capDir):
    debug(capDir, COLORS.BLUE)
    caps = get_captures(capDir)
    devices = get_devies(caps)

    csvCong = conglomerate_data(devices)
    csvCong.to_csv("./test.csv")

if __name__ == "__main__":
    if(len(sys.argv)==2):
        CAPTURE_DIR = sys.argv[1]
        
    main(CAPTURE_DIR)
