import os, sys
import pandas as pds, numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (roc_auc_score, 
                             accuracy_score,
                             balanced_accuracy_score,
                             precision_recall_fscore_support, 
                             confusion_matrix)


#extend this class to implement your own ML algorithm (or specific fine tunning of something such as how you shuffle data). Simply extend this class and override (see MLP class below for example)
class MachineLearningModel:
	def __init__(self, congDF, config):
		self.congDF = congDF
		self.config = config
		
		self.balance()
		self.shuffle_split()
		self.standardize()
		self.train_model()

	def balance(self):
		#This is my super readable, super big brain undersampling code which we shouldn't use. (keeping just in case our data in unbalanced and gives us bad results) 
		# 	shuffle = self.congDF.sample(frac=1)
        # 	shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([self.congDF.index])]
        # 	self.train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
        # 	self.test = pds.DataFrame().append([splt[1] for splt in shuffled_split])
		self.balanced = self.congDF

	def shuffle_split(self):
		self.xTR,self.xTE,self.yTR,self.yTE = train_test_split(self.balanced.values,self.balanced.index.values,train_size=0.8)

	def standardize(self):
		self.scaler = StandardScaler()
		self.scaler.fit(self.xTR)
		self.xTR = self.scaler.transform(self.xTR)
		self.xTE = self.scaler.transform(self.xTE)

	def score(self):
		self.predicted = self.clf.predict(self.xTE)
		self.predictedProb = self.clf.predict_proba(self.xTE)
		resDict = {}
		resDict["ACC"] = accuracy_score(self.yTE, self.predicted)
		resDict["bACC"] = balanced_accuracy_score(self.yTE, self.predicted)
		prec, rec, fscore, supp = precision_recall_fscore_support(self.yTE, self.predicted, average='weighted', zero_division=0)
		resDict.update({"PRECISION":prec, "RECALL":rec, "FSCORE":fscore})
		return resDict

	def train_model(self):
		pass


class MLP(MachineLearningModel):
	def train_model(self):
        	self.clf = MLPClassifier(solver='sgd', alpha=1e-5, hidden_layer_sizes=self.config["hiddenLayers"], learning_rate_init=0.001, random_state=1,max_iter=300)
        	self.clf.fit(self.xTR, self.yTR)

	def score(self):
		resDict = super().score()
		# print(self.predictedProb.shape)
		yPred = (self.predictedProb if self.predictedProb.shape[1]>2 else self.predictedProb[:,1])
		# print(yPred.shape)
		resDict["rAUC"] = roc_auc_score(self.yTE, yPred, multi_class="ovr")
		self.results = resDict
		return resDict









def generate_TestData(nClasses=15, nRows=10000, nColumns=500):
    return pds.DataFrame(np.random.randint(0,10,(nRows,nColumns-1)), index=np.random.randint(0,nClasses, nRows))

GEN_DATA=True
if __name__=="__main__":
	df = pds.DataFrame()
	if(GEN_DATA):
		df = generate_TestData(nClasses=15, nRows=10000, nColumns=100)
	else:
		if(len(sys.argv)!=2):
			raise ValueError("MLPipe expects one argument specifying the path of the dataset CSV.")
		else:
			toOpen=inputDir+sys.argv[1]+'.csv'
			print("Opening file %s" % toOpen)
			df = pds.read_csv(toOpen,index_col=0)

	MLPa = MLP(df,{"hiddenLayers":[20,10,5]})

	results = MLPa.score()
	print('MLP a:')
	print(MLPa.results)
