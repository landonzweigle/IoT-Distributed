import pyshark,sys,os,getopt,csv,pandas,numpy
import concurrent.futures as fts
from collections import Counter
import math,copy,re
import nest_asyncio
nest_asyncio.apply()
storeDir = "./windowParsed/"
capDir = "./Captures"
windowSize = 5
numWindows = 300


def calcEntropy(data):
	dataSize = len(data)
	ent = 0.0
	freq={}
	for c in data:
		freq[c] = freq.get(c, 0)+1
	for key in freq.keys():
		f = float(freq[key])/dataSize
		if f > 0: # to avoid an error for log(0)
			ent = ent + f * math.log(f, 2)
	return -ent
def getPayload(packet):
	if packet.transport_layer == "TCP":
		if hasattr(packet.tcp,"payload"):
			return packet.tcp.payload
	elif packet.transport_layer == "UDP":
		if hasattr(packet.udp,"payload"):
			return packet.udp.payload
	if hasattr(packet,"data"):
		if hasattr(packet.data,"data"):
			return packet.data.data
	raise Exception("no payload in packet")
def windowFlow(window):
	dict = {}
	rv = 0
	for packet in window:
		if not hasattr(packet,"ip"): continue
		tuple = (packet.ip.src, packet.ip.dst)
		dict[tuple] = dict[tuple] + 1 if tuple in dict else 1
		if dict[tuple] > rv:
			rv = dict[tuple]
	return {"iPFlow":rv}

def packetFeatures(packet,a):
	network = {"IP"+a:0,"IPv"+a:0,"ICMP"+a:0,"ICMPv6"+a:0}
	transport = {"srcPrt"+a:0,"dstPrt"+a:0,"UDP"+a:0,"TCPseq"+a:0,"TCPack"+a:0,"winSize"+a:0,"hdrLen"+a:0}
	payload = {"DHCP"+a:0,"length"+a:0,"entropy"+a:0}
	try:
		network["IPv"+a] = packet.ip.version
		network["IP"+a] = 1
		network["ICMP"+a] = int(packet.ip.proto == 1)
		network["ICMPv6"+a] = int(packet.ip.proto == 58)
	except AttributeError: pass
	try:
		if packet.transport_layer == "TCP":
			transport["srcPrt"+a] = packet.tcp.srcport
			transport["dstPrt"+a] = packet.tcp.dstport
			transport["TCPseq"+a] = packet.tcp.seq
			transport["TCPack"+a] = packet.tcp.ack
			transport["winSize"+a] = packet.tcp.window_size
			transport["hdrLen"+a] = packet.tcp.hdr_len
		elif packet.transport_layer == "UDP":
			transport["srcPrt"+a] = packet.udp.srcport
			transport["dstPrt"+a] = packet.udp.dstport
			transport["UDP"+a] = 1
			transport["hdrLen"+a] = packet.udp.hdr_len
	except AttributeError: pass
	try:
		payload["DHCP"+a] = int(packet.ip.src == '0.0.0.0' and packet.ip.dst == '255.255.255.255')
	except AttributeError: pass
	try:
		payloadData = getPayload(packet)
		payload["length"+a] = len(payloadData)
		payload["entropy"+a] = calcEntropy(payloadData)
	except: pass
	return {**network,**transport,**payload}
#-------------------------------------------------------------------------------------------------------------

class windowFrame:
	def __init__(self,window):
		self.df = windowFlow(window)
		self.window = window
		self.addPacketFeats()
	def addPacketFeats(self):
		for i in range(len(self.window)):
			self.df = {**self.df,**packetFeatures(self.window[i],"_"+str(i))}
class windowBuilder:
	def __init__(self,windowSize,name):
		self.windowSize = windowSize
		self.window = []
		self.windowArray = []
		self.name = name
	def size(self):
		return len(self.windowArray)
	def append(self,window):
		self.window.append(window)
		if len(self.window)>=self.windowSize:
			self.windowArray.append(windowFrame(self.window))
			self.window = []
	def __len__(self):
		return len(self.windowArray)
	

class windowArray:
	def __init__(self):
		self.windows = []
		self.count = 0
	def append(self,windowFrame,label):
		window = {**{'label':label},**windowFrame.df} if not 'label' in windowFrame.df else windowFrame.df
		if self.count <= 0:
			self.columns = [key for key in window.keys()]
		self.count += 1
		self.windows.append(window)
	def extend(self,windows,label):
		for window in windows.windowArray:
			self.append(window,label)
	def toDataframe(self):
		return pandas.DataFrame(data=self.windows,columns=self.columns)

#-----------------------------------------------------------------------------------------------------------






def filterIp(captures):
	getIps = lambda packet: (packet.ip.src,packet.ip.dst)
	start = 0
	while(start <= len(captures)):
		try:
			found = getIps(captures[start])
			break
		except AttributeError: start+=1
	if start >= len(captures):
		return "-1"
	checked = 0	##for debugging 
	for capture in captures[start:]:
		try:
        		current = getIps(capture)
		except AttributeError: continue
		checked+=1	##for debugging
		if not current[0] in found:
			return current[1]
		elif not current[1] in found:
			return current[0]
	print(f'checked for source ip in {checked} packets')	##for debugging
	return "-1"

def makeWindowArray(captures,builder):
	srcIp = filterIp(captures)
	debugPrint(f'source IP for {builder.name} = {srcIp} length of captures: {len(captures)}')
	if srcIp=="-1":
		print(f'no src ip found for {builder.name}')
	for packet in captures:
		if builder.size() >= numWindows: break
		if srcIp != "-1" and len(captures) > 20:
			try:
				if packet.ip.src != srcIp: continue
			except AttributeError as AE: continue
		builder.append(packet)

def readCapture(capture):
	captures = []
	for i in range(numWindows*10):
		try:
			captures.append(next(capture))
		except:
			break
	return captures
def fileDf(file):
	try:
		capture = pyshark.FileCapture(f'{capDir}/{file}.pcap')
	except: return
	debugPrint(f'reading from: {file}')
	captures = readCapture(iter(capture))
	capture.close()
	return captures





#-------------------------------------------------------------------------------------------
class fileExtractor:
	def __init__(self,name,files):
		self.files = list(filter(re.compile(name).match,files))
		self.builder = windowBuilder(windowSize,name)
		self.name = name
		self.readFiles()
	def readFiles(self):
		if len(self.files) <= 0:
			return
		with fts.ThreadPoolExecutor(max_workers=len(self.files)) as thr:
			run=[thr.submit(fileDf,file) for file in self.files]
			for thread in fts.as_completed(run):
				makeWindowArray(thread.result(),self.builder)
	def output(self,dict):
		debugPrint(f'creating df for {self.name}')
		dfArr = windowArray()
		for key,value in dict.items():
			print(f'{key}: {len(value.builder)} rows')
			dfArr.extend(value.builder,1 if key==self.name else 0)
		outDf = dfArr.toDataframe()
		outDf.to_csv(path_or_buf=f'{storeDir}{self.name}.csv',index=False)
		print(outDf)

def output(dict):
	for value in dict.values():
		value.output(dict)
def debugPrint(string):
	line = '-'*(len(string)+10)
	print(line)
	print(f'-----{string}-----')
	print(line)
#-------------------------------------------------------------------------------------------------------	
def makeFiles():
	inputFiles = []
	for f in os.listdir(capDir):
		if(f.split(".")[-1]=="pcap"):
			inputFiles.append(f.split(".")[0])
	return inputFiles

if __name__=="__main__":
	names = ['AmazonDot','AmazonEcho','AmazonShow','Awox','IDevice','IView','Musaic','cab','misc']
	files = makeFiles()
	extractors = {name:fileExtractor(name,files) for name in names}
	print(f'finished extractors init: {len(extractors)} created')
	output(extractors)
