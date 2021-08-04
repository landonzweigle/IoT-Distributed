import pyshark, sys, os, getopt, pandas

storeDir = "./windowParsed/"
windowSize = 5
numWindows = 5

def makeFiles(filename):
	outFileName = storeDir + filename + ".txt"
	inFileName = "./Captures/" + filename + ".pcap"
	if not os.path.exists(storeDir):
		os.mkdir(storeDir)
	if os.path.exists(inFileName):
		pcap = pyshark.FileCapture(inFileName)
	else:
		raise Exception(inFileName + ' not found')
	if os.path.exists(outFileName):
		os.remove(outFileName)
	outFile = open(outFileName, "w")
	print('reading from: ' + inFileName)
	print(pcap)
	print('storing in: ' + outFileName)
	return outFile, pcap

def makeFilesDf(filename):
	outFileName = storeDir + filename + ".csv"
	inFileName = "./Captures/" + filename + ".pcap"
	if not os.path.exists(storeDir):
		os.mkdir(storeDir)
	if os.path.exists(inFileName):
		pcap = pyshark.FileCapture(inFileName)
	else:
		raise Exception(inFileName + ' not found')
	with open(outFileName, 'w',newline='') as csvFile:
		csvWriter = csv.writer(csvFile, delimiter=',')
	print('reading from: ' + inFileName)
	print(pcap)
	print('storing in: ' + outFileName)
	return csvWriter, pcap

#---------------------------------------------------------------------------------
def packetId(packet):
	feats = {"IPsrc":0,"IPdst":0,"srcPrt":0,"dstPrt":0,"tLayer":'none'}
	try:
		feats["IPsrc"] = packet.ip.src
		feats["IPdst"] = packet.ip.dst
		if packet.transport_layer == "TCP":
			feats["srcPrt"] = packet.tcp.srcport
			feats["dstPrt"] = packet.tcp.dstport
			feats["tLayer"] = "TCP"
		elif packet.transport_layer == "UDP":
			feats["srcPrt"] = packet.udp.srcport
			feats["dstPrt"] = packet.udp.dstport
			feats["tLayer"] = "UDP"
		else:
			feats["tLayer"] = packet.transport_layer
	except AttributeError:
		print('error extracting features')
	return feats

def features(packet):
	feats = []
	try:
		
	except AttributeError:
		print('error extracting features')
	return feats

def makeDf(window):
	df = []
	for packet in window:
		df.append(packetId(packet))
		df.append(features(packet))
	return df

#---------------------------------------------------------------#
#---------------------------WINHOLDER?--------------------------#
#---------------------------------------------------------------#


class WinHolder:
	def __init__(self,packets):
		self.window = packets
		self.df = makeDf(self.window)

	def equals(self,rhs):
		return self.window == rhs.window

	#We can implement this method later to write the features from the window into a csv
	def writeDf(self,csvWriter):
		csvWriter.writerow(self.df)
		return csvWriter

	def testing(self):
		print('window: numPackets = ' + str(len(self.window)) )
		for packet in self.window:
			print(str(packetId(packet)))
	def writeFile(self,file):
		file.write('packets: ' + str(len(self.window)) + '\n')
		index = 0
		for packet in self.window:
			file.write('[' + str(index) + ']' + str(packetId(packet)) + '\n')
			index = index + 1
		file.write('\n')
		
#---------------------------------------------------------------------------------


def buildArrayLoop(captures):
	full = pds.DataFrame()
	for i in range(numWindows):
		window = captures[i:][windowSize:]
		toAppend = extract_features(window)
		full.append(toAppend, ignore_index=True)
	return full


def extract_features(window):


def main(argv):
	try:
		opts, args = getopt.getopt(argv,"f:s:n:")
		filename = 'none'
		for opt, arg in opts:
			if opt in ['-f']:
				filename = arg
			elif opt in ['-s']:
				windowSize = int(arg)
			elif opt in ['-n']:
				numWindows = int(arg)
		if filename == 'none':
			print('no filename given, call with -f \'filename\'')
			sys.exit()
		else:
			try:
				storage, pcap = makeFiles(filename)
			except Exception as error:
				print(error)
				sys.exit()
	except:
		print('bad arguments, -f for filename[mandatory argument], -s for size of window, -n for number of windows')
		sys.exit()
	captures = []
	for packet in pcap:
		captures.append(packet)
	return storage, captures	


	
if __name__=="__main__":
	storage, captures = main(sys.argv[1:])
#	windowArray = buildArray(captures,[],0)
	try:
		windowArrayB = buildArrayLoop(captures)
	except Exception as e:
		print(e)
#	for i in range (len(windowArray)):
#		if not windowArray[i].equals(windowArrayB[i]):
#			print('arrays are different')
	for window in windowArrayB:
		window.writeFile(storage)
	storage.close()
#-------------------------for testing/debugging------------------------------------
	for window in windowArrayB:
		window.testing()
#	print('checkpointC')
