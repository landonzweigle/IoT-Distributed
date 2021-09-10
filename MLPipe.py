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

#For the RNN:
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.metrics import *

#extend this class to implement your own ML algorithm (or specific fine tunning of something such as how you shuffle data). Simply extend this class and override (see MLP class below for example)
class MachineLearningModel:
	#congDF (for conglomerate dataframe) should be a pandas dataframe which contains the Y axis/data as the label, and everything else as the X axis/data.
	#if using kFoldCV, kFoldCV must be an int representing the number of folds. otherwise, set to False or None.
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config=None):
		self.congDF=congDF
		self.config=config
		self.kFoldCV = kFoldCV
		self.groupSplit = groupSplit

		#split the data into labels to ballance the data:
		self.shuffle_split()
		#scale (normalize) the data:
		self.standardize()
		#Train the model:
		self.train_model()

	def shuffle_split(self):
		def split(df):
			if(self.groupSplit):
				#shuffle the data:
				shuffle = df.sample(frac=1)

				shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([shuffle.index])]
				train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
				test = pds.DataFrame().append([splt[1] for splt in shuffled_split])

				xTR = train.values
				xTE = test.values
				yTR = train.index.values
				yTE = test.index.values
				#print("yTR len %i -- true len %i -- sum %i"%(len(yTR), len(train[train.index==1]), yTR.sum()))
				#print("yTE len %i -- true len %i -- sum %i"%(len(yTE), len(test[test.index==1]), yTE.sum()))

			else:
				xTR, xTE, yTR, yTE = train_test_split(df.values, df.index.values,train_size=0.8)
			return xTR, xTE, yTR, yTE
			

		if(self.kFoldCV):
			self.splits = [split(self.congDF) for i in range(self.kFoldCV)]
		else:
			self.splits = [train_test_split(self.congDF.values,self.congDF.index.values,train_size=0.8)]

	def standardize(self):
		standardSplits=[]
		for xTR, xTE, yTR, yTE in self.splits:
			scaler=StandardScaler()
			scaler.fit(xTR)

			standardSplits.append([scaler.transform(xTR), scaler.transform(xTE), yTR, yTE])
			#print("** yTR len %i -- sum %i"% (len(yTR), yTR.sum()))
			#print("** yTE len %i -- sum %i"% (len(yTE), yTE.sum()))
		self.standardSplits = standardSplits


	#Return a dict of each metric.
	def score(self):
		self.resArr = []
		for i, clf in enumerate(self.clfs):
			xTR, xTE, yTR, yTE = self.standardSplits[i]

			predicted = clf.predict(xTE)
			predictedProb = clf.predict_proba(xTE)

			resDict = {}
			resDict["ACC"] = accuracy_score(yTE, predicted)
			resDict["bACC"] = balanced_accuracy_score(yTE, predicted)
			prec, rec, fscore, supp = precision_recall_fscore_support(yTE, predicted, average='weighted', zero_division=0)

			tn, fp, fn, tp = confusion_matrix(yTE, predicted).ravel()

			rAUC = roc_auc_score(yTE, (predictedProb if predictedProb.shape[1]>2 else predictedProb[:,1]), multi_class="ovr")

			resDict.update({"PRECISION":prec, "RECALL":rec, "FSCORE":fscore, "rAUC":rAUC, "True Negative":tn, "False Negative":fn, "False Positive":fp, "True Positive":tp})

			self.resArr.append(resDict)

		self.results = pds.DataFrame(self.resArr)
		return self.results

	def train_model(self):
		pass


class MLP(MachineLearningModel):
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config={"hiddenLayers":[10,20]}):
		super().__init__(congDF, kFoldCV, groupSplit, config)
		return

	def train_model(self):
		#note: hidden layer is the total number of layers-2 (DOES NOT include input and output layers; I presume that implies that setup is automatic.)
		self.clfs = []
		for xTR, xTE, yTR, yTE in self.standardSplits:
			clf = MLPClassifier(solver='sgd', alpha=1e-5, hidden_layer_sizes=self.config["hiddenLayers"], learning_rate_init=0.01, max_iter=700)
			clf.fit(xTR, yTR)
			self.clfs.append(clf)

class RNN(MachineLearningModel):
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config={"hiddenLayers":[10,20]}):
		super().__init__(congDF, kFoldCV, groupSplit, config)
		return
		


	def train_model(self):
		self.clfs = []
		for xTR, xTE, yTR, yTE in self.standardSplits:
			model = keras.Sequential()
			# Add an Embedding layer expecting input vocab of size 1000, and
			# output embedding dimension of size 64.
			
			# model.add(layers.Embedding(input_length=self.congDF.shape[1],input_dim=int(np.amax(xTR)), output_dim=64))
			# Add a LSTM layer with 128 internal units.
			# model.add(layers.LSTM(128))
			model.add(layers.SimpleRNN(64,input_shape=(10,4)))

			# Add a Dense layer with 1 units.
			model.add(layers.Dense(1))
			#TN, FP, FN, TP
			model.compile(optimizer='adam', loss='binary_crossentropy', metrics=["Accuracy", "BinaryAccuracy", "AUC", "Precision", "Recall", "TrueNegatives", "FalsePositives", "FalseNegatives", "TruePositives"])
			print(model.summary())

			model.fit(xTR, yTR)
			self.clfs.append(model)

	def score(self):
		self.resArr = []
		for i, clf in enumerate(self.clfs):
			xTR, xTE, yTR, yTE = self.standardSplits[i]
			loss, accuracy, binAcc, AUC, prec, rec, tn, fp, fn, tp = clf.evaluate(xTE, yTE)
			self.resArr.append({"ACC": accuracy, "bACC": binAcc, "PRECISION":prec, "RECALL":rec, "rAUC":AUC, "True Negative":tn, "False Negative":fn, "False Positive":fp, "True Positive":tp})
		self.results=pds.DataFrame(resArr)
		return 0



def generate_TestData(nClasses=15, nRows=10000, nColumns=500):
	return pds.DataFrame(np.random.randint(0,10,(nRows,nColumns)), index=np.random.randint(0,nClasses, nRows))

GEN_DATA=True
if __name__=="__main__":
	df = pds.DataFrame()
	if(GEN_DATA):
		df = generate_TestData(nClasses=2, nRows=50, nColumns=1000)
	else:
		if(len(sys.argv)!=2):
			raise ValueError("MLPipe expects one argument specifying the path of the dataset CSV.")
		else:
			toOpen=sys.argv[1]
			print("Opening file %s" % toOpen)
			df = pds.read_csv(toOpen,index_col=0)

	RNN = RNN(df,kFoldCV=1)
	results = RNN.score()
	print(RNN.results)
	print(RNN.results.mean())
