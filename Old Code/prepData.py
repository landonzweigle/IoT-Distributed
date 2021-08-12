import pyshark
import sys
import os
import getopt
import csv
import pandas
import numpy
import ipaddress
storeDir = "./windowParsed/"
capDir = "./Captures"
windowSize = 5
numWindows = 10

#--------------------------------------------------------------------------------------------------
def toInt(ip):
	addr = ipaddress.ip_address(ip)
	return int(addr)

def ipFeats(packet,a):
	feats = {"IP"+a:0,"IPv"+a:0,"IPsrc"+a:0,"IPdst"+a:0,"ICMP"+a:0,"ICMPv6"+a:0}
#	feats = {name:numpy.NAN for name in feats}
	try:
		if hasattr(packet,"ip"):
			feats["IPv"+a] = packet.ip.version
			feats["IPsrc"+a] = toInt(packet.ip.src)
			feats["IPdst"+a] = toInt(packet.ip.dst)
			feats["IPhdrLen"+a] = packet.ip.hdr_len
			feats["IP"+a] = 1
			feats["ICMP"+a] = int(packet.ip.proto == 1)
			feats["ICMPv6"+a] = int(packet.ip.proto == 58)
	except AttributeError:
		print('error extracting features: network')
	return feats

def tlFeats(packet,a):
	feats = {"srcPrt"+a:0,"dstPrt"+a:0,"TCP"+a:0,"UDP"+a:0,"TCPseq"+a:0,"TCPack"+a:0,"winSize"+a:0,"hdrLen"+a:0}
#	feats = {name:numpy.NAN for name in feats}
	try:
		if packet.transport_layer == "TCP":
			feats["srcPrt"+a] = packet.tcp.srcport
			feats["dstPrt"+a] = packet.tcp.dstport
			feats["TCP"+a] = 1
			feats["TCPseq"+a] = packet.tcp.seq
			feats["TCPack"+a] = packet.tcp.ack
			feats["winSize"+a] = packet.tcp.window_size
			feats["hdrLen"+a] = packet.tcp.hdr_len
		elif packet.transport_layer == "UDP":
			feats["srcPrt"+a] = packet.udp.srcport
			feats["dstPrt"+a] = packet.udp.dstport
			feats["UDP"+a] = 1
			feats["hdrLen"+a] = packet.udp.hdr_len
	except AttributeError:
		print('error extracting features: transport')
	return feats

def calcEntropy(data):
	dataSize = len(data)
	ent = 0.0
	freq={}
	for c in data:
		freq[c] = freq.get(c, 0)+1
	for key in freq.keys():
		f = float(freq[key])/dataSize
		if f > 0: # to avoid an error for log(0)
			ent = ent + f * math.log(f, LOG_BASE)
	return -ent

def getPayload(packet,a):
	feats = {"DHCP"+a:0,"length"+a:0,"entropy"+a:0}
#	feats = {name:numpy.NAN for name in feats}
	try:
		feats["DHCP"+a] = int(toInt(packet.ip.src) == 0 and toInt(packet.ip.dst) == 0xFFFFFFFF)
	except AttributeError:
		print('error extracting features: payload')
	if not hasattr(packet,"data"):
		return feats
	if not hasattr(packet.data,"data"):		
		return feats
	payload = packet.data.data
	feats["length"+a] = len(payload)
	feats["entropy"+a] = calcEntropy(payload)
	return feats

def addCols(df,dict):
	for key,value in dict.items():
		df.insert(len(df.columns),key,[value])
	return df

def packetFeat(packet,index,df):
	label = "_"+str(index)
	df = addCols(df,ipFeats(packet,label))
	df = addCols(df,tlFeats(packet,label))
	df = addCols(df,getPayload(packet,label))
	return df

def windowFeat(window,label):
	df = pandas.DataFrame()
	df = addCols(df,{"label":label})
	for i in range(len(window)):
		df = packetFeat(window[i],i,df)
	return df

#---------------------------------------------------------------------------------
def window(pcap,windowSize,num,label):
	if os.path.exists(pcap):
		capture = pyshark.FileCapture(pcap)
	else:
		raise Exception(pcap + ' not found')
	captures = [packet for packet in capture]
	while(len(captures)<(windowSize+num)):
		num-=1
	windowArray = [captures[i:i+windowSize] for i in range(num)]
	df = pandas.DataFrame()
	for window in windowArray:
		df = df.append(windowFeat(window,label) )
	return df

#-------------------------------------------------------
def makeFiles(positive):
	inputFiles = []
	for f in os.listdir(capDir):
		if(f.split(".")[-1]=="pcap"):
			inputFiles.append(f.split(".")[0])
	if not os.path.exists(storeDir):
		print('creating directory: ' + storeDir)
		os.mkdir(storeDir)
	csvFile = open(storeDir+positive+'.csv','w',newline='')
	for file in inputFiles:
		print(file)
	return csvFile,inputFiles

def FileDF(df,file,label):
	if label == 1:
		print('reading positive data from: ' + file)
	else:
		print('reading negative data from: ' + file)
	try:
		df = df.append(window(capDir+'/'+file+'.pcap',windowSize,numWindows,label))
	except Exception as e:
		print(e)
	return df

def makeDf(input,positive):
	df = pandas.DataFrame()
	for file in input:
		label = (int)(file[:len(positive)]==positive)
		df = FileDF(df,file,label)
	return df	

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
	except:
		print('bad arguments, -f for positiveFile[mandatory argument], -s for size of window, -n for number of windows')
		sys.exit()
	return filename

if __name__=="__main__":
	positive = main(sys.argv[1:])
	storage,inputs = makeFiles(positive)
	df = makeDf(inputs,positive)
	print('finished making dataframe')
	print(df)
	df.to_csv(path_or_buf=storage)
	storage.close()

		