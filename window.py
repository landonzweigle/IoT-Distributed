import pyshark, sys, os, getopt
import pandas as pds
from math import ceil
from numpy import float128

storeDir = "./windowParsed/"
windowSize = 5
numWindows = 5
FILTER_PACKETS = False

def makeFiles(filename):
	outFileName = storeDir + filename + ".csv"
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
	# print(pcap)
	print('storing in: ' + outFileName)
	print("-------------------------------------")
	print("PCAP DIR:")
	for a in dir(pcap):
		print(a)
	print("-------------------------------------")
	print("PACKET DIR:")
	for a in dir(pcap[0]):
		print(a)
	print("-------------------------------------")
	return outFile, pcap


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


def build_windows(captures):
	full = pds.DataFrame()
	frameIDArr = []

	overlapMustBeFull=True
	useOverlap=True

	baseTime = float128(captures[0].sniff_timestamp)
	print("Building windows from %i packets"%len(captures))

	#decide the max number i should be (and step size) depending on if the windows overlap or not.
	filteredCaps = filter_packets(captures)
	nonOverlapCount = len(filteredCaps)			#ceil(len(filteredCaps)/windowSize)
	overlapCount = len(filteredCaps) if(not overlapMustBeFull) else (len(filteredCaps)-windowSize+1)
	maxCount, stepSize = (overlapCount,1) if(useOverlap) else (nonOverlapCount, windowSize)

	print("max count: %i, step size: %i" %(maxCount, stepSize))

	for i in range(0, maxCount, stepSize): #we can change step to windowsize to do a non-inclusive window building (e.g. 1-5, 5-10, )
		#window full is every packet after this windows starting packet so "bad"/unrelevant packets can be sorted out.
		window = filteredCaps[i:i+windowSize]
		extracted, frameIDs = extract_features(window, baseTime)
		frameIDArr.append(frameIDs)
		full.append(extracted, ignore_index=True)
	print(frameIDArr)
	return full


#returns a DataFrame of the features extracted.
#This is what we extract:
#Packet Header Features{
#	ARP* 			[0,1]
#	IP				[0,1]
#	ICMP			[0,1]
#	ICMPV6			[0,1]
#	EAPoL			[0,1]
#	TCP				[0,1]
#	UDP				[0,1]
#	HTTP			[0,1]
#	HTTPS			[0,1]
#	DHCP			[0,1]
#	BOOTP			[0,1]
#	SSDP			[0,1]
#	DNS				[0,1]
#	MDNS			[0,1]
#	NTP				[0,1]
#	Padding			[0,1]
#	Router Alert	[0,1]
#}
#Payload Based Features{
#	Entropy
#	TCP Window Size
#	Payload Length
#}
def extract_features(captures):
	def getTimes():
		timeOffset = round(float128(packet.sniff_timestamp) - firstTime,9)
		return timeOffset

	def getFrameNumber():
		return packet.number

	def getFrameLength():
		return packet.length

	firstTime = float128(captures[0].sniff_timestamp)

	packets = []
	frameNums = []

	for frameID, packet, in enumerate(captures):
		dictPrefix = "Frame[%s]"%(frameID)
		frameDict = {}

		frameNum = getFrameNumber()
		frameNums.append(frameNum)
		frameDict["%s-Frame Number"%dictPrefix] = frameNum

		frameDict["%s-Frame Length"%dictPrefix] = getFrameLength()

		timeOffset = getTimes()
		frameDict["%s-Time"%dictPrefix] = timeOffset

		# print(packet)
		print(frameDict)
		packets.append(frameDict)
		print("------------------")

	print("******************************************************")
	return packets, frameNums

#Filters packets and returns an array with only n=windowSize packets
def filter_packets(winAll):
	if(FILTER_PACKETS):
		#this doesnt make sense at all but whatever :)
		filtered=winAll
	else:
		filtered = winAll
	return filtered

#determines if the packet is out of the device.
#[TBI], we don't know the devices IP at the time of capture so we could only do a best guess.
def outgoing_packet(packet):
	pass

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

	features, frameNums = extract_features(captures)
	print(features)
	# windowArray = build_windows(captures)



#-------------------------for testing/debugging------------------------------------
	# for window in windowArrayB:
	# 	window.testing()
#	print('checkpointC')
