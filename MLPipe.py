import os
import pandas as pds, numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split


class MLP:
    #congDF (for conglomerate dataframe) should be a pandas dataframe which contains the Y axis/data as the label, and everything else as the X axis/data.
    def __init__(self, congDF):
        self.congDF = congDF

        #split the data into labels to ballance the data:
        shuffle = self.congDF.sample(frac=1)
        shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([self.congDF.index])]
        self.train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
        self.test = pds.DataFrame().append([splt[1] for splt in shuffled_split])
        print("Train len: %d, Test len: %d, Test Ratio: %d" % (len(self.train), len(self.test), len(self.train)//(len(self.train) + len(self.test))))





def generate_TestData(nClasses=15, nRows=10000, nColumns=500):
    return pds.DataFrame(np.random.randint(0,10,(nRows,nColumns-1)), index=np.random.randint(0,nClasses-1, nRows))

GEN_DATA=True
if __name__=="__main__":
    df = pds.DataFrame
    if(GEN_DATA):
        df = generate_TestData(nRows=10000, nColumns=20)
    #print(df)
    MLP = MLP(df)
