import os, sys
import pandas as pds, numpy as np, concurrent.futures as futures
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (roc_auc_score, 
							accuracy_score,
							balanced_accuracy_score,
							precision_recall_fscore_support, 
							confusion_matrix)


from Utility import *

#For the RNN:
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.metrics import *

#extend this class to implement your own ML algorithm (or specific fine tunning of something such as how you shuffle data). Simply extend this class and override (see MLP class below for example)
class MachineLearningModel:
	#congDF (for conglomerate dataframe) should be a pandas dataframe which contains the Y axis/data as the label, and everything else as the X axis/data.
	#if using kFoldCV, kFoldCV must be an int representing the number of folds. otherwise, set to False or None.
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config=None, fast=True):
		self.congDF = congDF
		self.config = config
		self.kFoldCV = kFoldCV if isinstance(kFoldCV,int) else 1
		self.groupSplit = groupSplit

		self.standardSplits = []
		self.clfs = []

		debug("Processing Data (Splitting and standardizing).",COLORS.BLUE)
		for i in range(self.kFoldCV):
			xTR, xTE, yTR, yTE = self.shuffle_split(self.congDF, self.groupSplit)
			xTRst, xTEst = self.standardize(xTR, xTE)
			self.standardSplits.append([xTRst, xTEst, yTR, yTE])

		debug("Training model... Fast Mode:%s"%fast,COLORS.GREEN)
		if(fast):
			with futures.ProcessPoolExecutor(max_workers=self.kFoldCV) as executer:
				running = [executer.submit(self.train_model, xTR, xTE, yTR, yTE, self.config) for xTR, xTE, yTR, yTE in self.standardSplits]

				for res in futures.as_completed(running):
					self.clfs.append(res.result())
		else:
			for i, (xTR, xTE, yTR, yTE) in enumerate(self.standardSplits):
				self.clfs.append(self.train_model(xTR, xTE, yTR, yTE, self.config))

	#Return a dict of each metric.
	def score(self,unseen=None):
		resArr = []
		for i, clf in enumerate(self.clfs):
			IGN, xTE, IGN, yTE = self.standardSplits[i] if(unseen==None) else (None, unseen[0], None, unseen[1])

			predicted = clf.predict(xTE)
			predictedProb = clf.predict_proba(xTE)

			resDict = {}
			resDict["ACC"] = accuracy_score(yTE, predicted)
			resDict["bACC"] = balanced_accuracy_score(yTE, predicted)
			prec, rec, fscore, supp = precision_recall_fscore_support(yTE, predicted, average='weighted', zero_division=0)

			tn, fp, fn, tp = confusion_matrix(yTE, predicted,labels=[0,1]).ravel()


			rAUC = (roc_auc_score(yTE, (predictedProb if predictedProb.shape[1]>2 else predictedProb[:,1]), multi_class="ovr")) if(len(np.unique(yTE))>=2) else np.NAN

			resDict.update({"PRECISION":prec, "RECALL":rec, "FSCORE":fscore, "rAUC":rAUC, "True Negative":tn, "False Negative":fn, "False Positive":fp, "True Positive":tp})

			resArr.append(resDict)

		results = pds.DataFrame(resArr)
		return results

	def score_unseen(self,unseenDF):
		xUN = unseenDF.values
		yUN = unseenDF.index.values

		xUN, IGN, IGN, IGN = self.standardize(xUN,None)
		return self.score((xUN,yUN))

	@classmethod
	def shuffle_split(cls, df, groupSplit):
		if(groupSplit):
			#shuffle the data:
			shuffle = df.sample(frac=1)

			shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([shuffle.index])]
			train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
			test = pds.DataFrame().append([splt[1] for splt in shuffled_split])

			xTR = train.values
			xTE = test.values
			yTR = train.index.values
			yTE = test.index.values

		else:
			xTR, xTE, yTR, yTE = train_test_split(df.values, df.index.values,train_size=0.8)
		return xTR, xTE, yTR, yTE
			
	@classmethod
	def standardize(cls, xTR, xTE):
		scaler=StandardScaler()
		scaler.fit(xTR)

		xTRs = scaler.transform(xTR)
		xTEs = scaler.transform(xTE) if(isinstance(xTE,np.ndarray)) else None

		return xTRs, xTEs

	@classmethod
	def train_model(cls, xTR, xTE, yTR, yTE, config):
		pass

#---------------------------------------#
#------------------MLP------------------#
#---------------------------------------#

class MLP(MachineLearningModel):
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config={"hiddenLayers":[10,20]},fast=True):
		super().__init__(congDF, kFoldCV, groupSplit, config, fast)
		return

	@classmethod
	def train_model(cls, xTR, xTE, yTR, yTE, config):
		#note: hidden layer is the total number of layers-2 (DOES NOT include input and output layers; I presume that implies that setup is automatic.)
		clf = MLPClassifier(solver='sgd', alpha=1e-5, hidden_layer_sizes=config["hiddenLayers"], learning_rate_init=0.01, max_iter=700)
		clf.fit(xTR, yTR)
		return clf

#---------------------------------------#
#------------------RNN------------------#
#---------------------------------------#

class RNN(MachineLearningModel):
	numFeatsKey="num_features"
	winSizeKey ="win_size"

	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config={"num_features":None}, fast=True):
		#While I dislike not having the super init first, It can't really be helped :/
		if(not config.get(RNN.numFeatsKey, None)):
			raise Exception("RNN Requires config value of %s to run."%RNN.numFeatsKey)
		
		if(RNN.winSizeKey not in config):
			config[RNN.winSizeKey] = congDF.shape[1]//config[RNN.numFeatsKey]
		
		super().__init__(congDF, kFoldCV, groupSplit, config, fast)

		return
		
	@classmethod
	def fix_shape(cls, xTR, xTE, config):
		#We need to reshape xTR and xTE to be in the form [samples, time steps, features]
		xTR = xTR.reshape(xTR.shape[0], config[cls.winSizeKey], config[cls.numFeatsKey])
		xTE = xTE.reshape(xTE.shape[0], config[cls.winSizeKey], config[cls.numFeatsKey])

		return xTR, xTE

	@classmethod
	def train_model(cls, xTR, xTE, yTR, yTE, config):
		xTR, xTE = cls.fix_shape(xTR, xTE, config)

		model = keras.Sequential()
		# Add an Embedding layer expecting input vocab of size 1000, and
		# output embedding dimension of size 64.
		
		# model.add(layers.Embedding(input_length=self.congDF.shape[1],input_dim=int(np.amax(xTR)), output_dim=64))
		# Add a LSTM layer with 128 internal units.
		# model.add(layers.LSTM(128))
		model.add(layers.SimpleRNN(64,input_shape=(config[cls.winSizeKey], config[cls.numFeatsKey])))

		# Add a Dense layer with 1 units.
		model.add(layers.Dense(1))
		#TN, FP, FN, TP
		model.compile(optimizer='adam', loss='binary_crossentropy', metrics=["Accuracy", "BinaryAccuracy", "AUC", "Precision", "Recall", "TrueNegatives", "FalsePositives", "FalseNegatives", "TruePositives"])
		# print(model.summary())

		model.fit(xTR, yTR)
		return model

	def score(self):

		return pds.DataFrame({"NONE":[-1]})



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
