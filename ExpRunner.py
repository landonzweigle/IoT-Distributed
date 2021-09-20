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

    congDF, unseenDF = cleanDF(pds.read_csv(cong, index_col=0))

    debug(unseenDF,COLORS.ORANGE)

    winSize = len(set([a.split('-')[0] for a in congDF.columns])) - 2 #subtract 2 for the Device and frameID columns
    numFeats = congDF.shape[1]//winSize

    config = {MLPipe.RNN.numFeatsKey: numFeats}

    resIndex = []
    resData = []
    unseenData = []


    for uniqueName in congDF["Device"].unique():
        #get the numerical device ID
        devID = congDF[congDF["Device"]==uniqueName].index.unique()[0]
        print("DeviceID: %s"%devID)

        df = congDF.drop(["Device","frame ID"],axis=1)
        df.index = (df.index==devID).astype(int)

        dfRNN = MLPipe.RNN(df,kFoldCV=10, config=config)
        results = dfRNN.score()
        resIndex.append(uniqueName)
        resData.append(results.mean())

        # if(isinstance(unseenDF,pds.DataFrame)):
        #     debug("Testing unseen data.",COLORS.ORANGE)
        #     dfTest = unseenDF.drop(["Device","frame ID"],axis=1)
        #     dfTest.index = (dfTest.index==devID).astype(int)

        #     resUnseen = dfMLP.score_unseen(dfTest)

        #     unseenData.append(resUnseen.mean())
            

    resDF = pds.DataFrame(data=resData,index=resIndex)
    resUnseenDF = pds.DataFrame(data=unseenData,index=resIndex)

    debug(resDF,COLORS.BLUE)
    debug(resUnseenDF,COLORS.ORANGE)

    fullResDF = pds.concat({"Seen Data":resDF,"Unseen Data":resUnseenDF},axis=1)
    
    #resDF.to_csv(saveFile)
    fullResDF.to_csv(saveFile)
    return fullResDF

def cleanDF(df,removeSmall=False):
    #drop every column where there exists only na values: 
    df = df.dropna(axis=1, how='all')
    df = df.fillna(-1)

    #Remove devices that have too few data:
    if(removeSmall):
        lenDF = pds.DataFrame([{"NAME":dfg["Device"].values[-1],"N":len(dfg)} for _,dfg in df.groupby("Device")])
        print(lenDF)
        removed= lenDF[lenDF.isin(lenDF[lenDF["N"]>0])==False].dropna()["NAME"].values
        a = list([debug("Device %s does not have enough data."%dev,COLORS.RED) for dev in removed])

    #Make sure there are zeros and ones only. If not just drop the column
    debug(len(df["Unseen"].unique()),COLORS.ORANGE)
    if(len(df["Unseen"].unique())==2):
        seen = df[df["Unseen"]==0].drop("Unseen",axis=1)
        unseen = df[df["Unseen"]==1].drop("Unseen",axis=1)
        return seen, unseen

    df = df.drop("Unseen",axis=1)

    return df, None
    

if __name__=="__main__":
    now = datetime.now().strftime("%m-%d-%y")
    savePath=get_unique_filename("results[%s].csv"%now)

    if(len(sys.argv)==2):
        print("using positional argument 'Conglomerate_In'")

    congIN = sys.argv[1] if len(sys.argv)==2 else None

    main(savePath, congIN)