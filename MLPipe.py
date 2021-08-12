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
	#congDF (for conglomerate dataframe) should be a pandas dataframe which contains the Y axis/data as the label, and everything else as the X axis/data.
	def __init__(self, congDF, config=None):
		self.congDF=congDF
		self.config=config

		#balance the data. Currently does nothing but set class variables
		self.balance()
		#split the data into labels to ballance the data:
		self.shuffle_split()
		#scale (normalize) the data:
		self.standardize()
		#Train the model:
		self.train_model()

	def balance(self):
		#This is my super readable, super big brain undersampling code which we shouldn't use. (keeping just in case our data in unbalanced and gives us bad results) 
		# 	shuffle = self.congDF.sample(frac=1)
		# 	shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([self.congDF.index])]
		# 	self.train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
		# 	self.test = pds.DataFrame().append([splt[1] for splt in shuffled_split])
		self.balanced = self.congDF

	def standardize(self):
		self.scaler = StandardScaler()
		#get fitting parameters from x train:
		self.scaler.fit(self.xTR)
		#apply the transformation:
		self.xTR = self.scaler.transform(self.xTR)
		self.xTE = self.scaler.transform(self.xTE)     

	def train_model(self):
		pass

	def shuffle_split(self):
		self.xTR,self.xTE,self.yTR,self.yTE = train_test_split(self.balanced.values,self.balanced.index.values,train_size=0.8)

		# print("Train len: %d, Test len: %d, Test Ratio: %s" % (len(self.train), len(self.test), float(len(self.train))/float(len(self.train) + len(self.test))))

	#Return a dict of each metric.
	def score(self):
		self.predicted = self.clf.predict(self.xTE)
		self.predictedProb = self.clf.predict_proba(self.xTE)

		resDict = {}
		resDict["ACC"] = accuracy_score(self.yTE, self.predicted)
		resDict["bACC"] = balanced_accuracy_score(self.yTE, self.predicted)
		prec, rec, fscore, supp = precision_recall_fscore_support(self.yTE, self.predicted, average='weighted', zero_division=0)
		
		tn, fp, fn, tp = confusion_matrix(self.yTE, self.predicted).ravel()

		resDict.update({"PRECISION":prec, "RECALL":rec, "FSCORE":fscore, "True Negative": tn, "False Positive": fp, "False Negative": fn, "True Positive": tp})

		return resDict



class MLP(MachineLearningModel):
	def __init__(self, congDF, config={"hiddenLayers":[10,20]}):
		super().__init__(congDF, config)

	def train_model(self):
		#note: hidden layer is the total number of layers-2 (DOES NOT include input and output layers; I presume that implies that setup is automatic.)
		self.clf = MLPClassifier(solver='sgd', alpha=1e-5, hidden_layer_sizes=self.config["hiddenLayers"], learning_rate_init=0.001, random_state=1,max_iter=300)
		self.clf.fit(self.xTR, self.yTR)

	def score(self):
		resDict = super().score()
		
		resDict["rAUC"] = roc_auc_score(self.yTE, (self.predictedProb if self.predictedProb.shape[1]>2 else self.predictedProb[:,1]), multi_class="ovr")
		self.results = resDict
		return resDict









def generate_TestData(nClasses=15, nRows=10000, nColumns=500):
	return pds.DataFrame(np.random.randint(0,10,(nRows,nColumns-1)), index=np.random.randint(0,nClasses, nRows))

GEN_DATA=True
if __name__=="__main__":
	df = pds.DataFrame()
	if(GEN_DATA):
		df = generate_TestData(nClasses=20, nRows=10000, nColumns=100)
	else:
		if(len(sys.argv)!=2):
			raise ValueError("MLPipe expects one argument specifying the path of the dataset CSV.")
		else:
			toOpen=sys.argv[1]
			print("Opening file %s" % toOpen)
			df = pds.read_csv(toOpen,index_col=0)

	MLP = MLP(df)
	results = MLP.score()
	print(MLP.results)