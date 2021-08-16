import os, sys, MLPipe
import pandas as pds
from datetime import datetime
from Utility import get_unique_filename

CONG_CSV="./windowParsed/Conglomerate.csv"

def main():
    cong = cleanDF(pds.read_csv(CONG_CSV, index_col=0))

    resIndex = []
    resData = []


    for uniqueName in cong["Device"].unique():
        devID = cong[cong["Device"]==uniqueName].index.unique()[0]
        print("DeviceID: %s"%devID)

        df = cong.drop("Device",axis=1)
        df.index = df.index.map(lambda x: int(x==devID))

        dfMLP = MLPipe.MLP(df)
        results = dfMLP.score()

        resIndex.append(uniqueName)
        resData.append(results)

    resDF = pds.DataFrame(data=resData,index=resIndex)
    print(resDF)
    
    now = datetime.now().strftime("%m-%d-%y")
    resDF.to_csv(get_unique_filename("results.csv"))
    return resDF

def cleanDF(df):
    #drop every column where there exists only na values: 
    df = df.dropna(axis=1, how='all')
    df = df.fillna(-1)
    return df
    

if __name__=="__main__":
    main()