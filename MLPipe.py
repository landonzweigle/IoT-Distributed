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
	#if using kFoldCV, kFoldCV must be an int representing the number of folds. otherwise, set to False or None.
	def __init__(self, congDF, kFoldCV=False, groupSplit=True, config=None):
		self.congDF=congDF
		self.config=config
		self.kFoldCV = kFoldCV
		self.groupSplit = groupSplit
		print(self.groupSplit)

		#split the data into labels to ballance the data:
		self.shuffle_split()
		#scale (normalize) the data:
		self.standardize()
		#Train the model:
		self.train_model()


	# def balance(self):
	# 	#This is my super readable, super big brain undersampling code which we shouldn't use. (keeping just in case our data in unbalanced and gives us bad results) 
	# 	# shuffle = self.congDF.sample(frac=1)
	# 	# shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([self.congDF.index])]
	# 	# self.train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
	# 	# self.test = pds.DataFrame().append([splt[1] for splt in shuffled_split])

	# 	self.balanced = self.congDF
	

	def shuffle_split(self):
		def split(df):
			if(self.groupSplit):
				#shuffle the data:
				print(":)")
				shuffle = df.sample(frac=1)

				shuffled_split = [list(train_test_split(c, test_size=0.2)) for ign, c in shuffle.groupby([shuffle.index])]
				# print(shuffled_split[0][0])
				# print("~~")
				# print(shuffled_split[0][1])

				# print("**")
				# print(shuffled_split[1][0])
				# print("~~")
				# print(shuffled_split[1][1])

				train = pds.DataFrame().append([splt[0] for splt in shuffled_split])
				test = pds.DataFrame().append([splt[1] for splt in shuffled_split])
				# print()
				# print(train)
				# print("---")
				# print(test)



				xTR = train.values
				xTE = test.values
				yTR = train.index.values
				yTE = test.index.values
				print("yTR len %i -- true len %i -- sum %i"%(len(yTR), len(train[train.index==1]), yTR.sum()))
				print("yTE len %i -- true len %i -- sum %i"%(len(yTE), len(test[test.index==1]), yTE.sum()))

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
			print("** yTR len %i -- sum %i"% (len(yTR), yTR.sum()))
			print("** yTE len %i -- sum %i"% (len(yTE), yTE.sum()))
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
			
			#tn, fp, fn, tp = confusion_matrix(yTE, predicted).ravel()
			CM = confusion_matrix(yTE, predicted)

			tn = CM[0][0]
			fn = CM[1][0]
			tp = CM[1][1]
			fp = CM[0][1]

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










def generate_TestData(nClasses=15, nRows=10000, nColumns=500):
	return pds.DataFrame(np.random.randint(0,10,(nRows,nColumns)), index=np.random.randint(0,nClasses, nRows))

GEN_DATA=True
if __name__=="__main__":
	df = pds.DataFrame()
	if(GEN_DATA):
		df = generate_TestData(nClasses=2, nRows=20, nColumns=10)
	else:
		if(len(sys.argv)!=2):
			raise ValueError("MLPipe expects one argument specifying the path of the dataset CSV.")
		else:
			toOpen=sys.argv[1]
			print("Opening file %s" % toOpen)
			df = pds.read_csv(toOpen,index_col=0)

	MLP = MLP(df,kFoldCV=1)
	results = MLP.score()
	print(MLP.results)
	print(MLP.results.mean())