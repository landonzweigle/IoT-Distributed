import os, sys, MLPipe
import pandas as pds, numpy as np
from datetime import datetime
from scipy import stats
from Utility import *   #get_unique_filename, raise_filePath_DNE, debug

CONG_DIR="./windowParsed"
CONG_NAME_BASE="Conglomerate"
CONG_NAME=CONG_NAME_BASE+".csv"
CONG_CSV=os.path.normpath(CONG_DIR + "/" + CONG_NAME)

def select_cong():
    files=os.listdir(CONG_DIR)
    biggestRaw = ""
    biggest = ""

    print(files)

    for f in files:
        if(os.path.isdir(f)):
            debug(f,COLORS.RED)
            continue
        if(f.startswith(CONG_NAME_BASE)):
            fRaw = f.split('.')[0].split(CONG_NAME_BASE)[-1]

            debug("'%s' > '%s' [?]"%(fRaw, biggestRaw),COLORS.BLUE)
            if(fRaw>biggestRaw):
                debug("\t-->'%s' > '%s' == True" % (f, biggest),COLORS.GREEN)
                biggestRaw=fRaw
                biggest=f
    return os.path.normpath(CONG_DIR+"/"+biggest)




def main(saveFile, cong=None):
    if(not cong):
        cong=select_cong()
    cong = raise_filePath_DNE(cong)
    if(os.path.isfile(cong)==False):
        raise Exception("Argument:'cong' is not a valid file.")

    debug("Using Conglomerate at %s"%cong, COLORS.GREEN)

    saveFile = raise_filePath_DNE(saveFile)

    congDF = cleanDF(pds.read_csv(cong, index_col=0))

    return

    resIndex = []
    resData = []


    for uniqueName in congDF["Device"].unique():
        devID = congDF[congDF["Device"]==uniqueName].index.unique()[0]
        print("DeviceID: %s"%devID)

        df = congDF.drop("Device",axis=1)
        df.index = df.index.map(lambda x: int(x==devID))

        dfMLP = MLPipe.MLP(df)
        results = dfMLP.score()
        resIndex.append(uniqueName)
        resData.append(results)

    resDF = pds.DataFrame(data=resData,index=resIndex)
    print(resDF)
    
    resDF.to_csv(saveFile)
    return resDF

def cleanDF(df):
    #drop every column where there exists only na values: 
    df = df.dropna(axis=1, how='all')
    df = df.fillna(-1)

    lenDF = pds.DataFrame([{"NAME":dfg["Device"].values[-1],"N":len(dfg)} for _,dfg in df.groupby("Device")])

    removed= lenDF[lenDF.isin(lenDF[lenDF["N"]>10])==False].dropna()["NAME"].values
    a = list([debug("Device %s does not have enough data."%dev,COLORS.RED) for dev in removed])

    return df
    

if __name__=="__main__":
    now = datetime.now().strftime("%m-%d-%y")
    savePath=get_unique_filename("results[%s].csv"%now)

    if(len(sys.argv)==2):
        print("using positional argument 'Conglomerate_In'")

    congIN = sys.argv[1] if len(sys.argv)==2 else None

    main(savePath, congIN)