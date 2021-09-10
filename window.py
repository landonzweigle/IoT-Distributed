import pyshark, sys, os, getopt
import pandas as pds, numpy as np
import math
from Utility import *
from numpy import float128

storeDir = "./windowParsed/"
windowSize = 5
# numWindows = 5
LOG_BASE = 2 # math.e
FILTER_PACKETS = False

INIT_DEBUG=False

#self debug. Will only debug if this is the *MAIN CLASS* being ran.
def sDebug(msg, col):
	if(__name__=="__main__"):
		debug(msg,col)


def makeFiles(filename):
	outFileName = storeDir + filename + ".csv"
	inFileName = "./Captures/" + filename + ".pcap"
	if not os.path.exists(storeDir):
		os.mkdir(storeDir)
	if os.path.exists(inFileName):
		pcap = pyshark.FileCapture(inFileName)#, display_filter="dns")
	else:
		raise Exception(inFileName + ' not found')
	if os.path.exists(outFileName):
		os.remove(outFileName)
	if(INIT_DEBUG):
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
		print("Layer0:")
		for a in dir(pcap[0].layers[1]):
			debug(a,COLORS.ORANGE)
		# debug([p.layers for p in pcap],COLORS.BLUE)
		for p in pcap:
			debug([layer.layer_name.upper() for layer in p.layers],COLORS.RED)
		print("-------------------------------------")
		print("Layers:")
		for a in dir(pcap[0].layers):
			print(a)
		debug(pcap[0].layers,COLORS.ORANGE)
		debug(type(pcap[0].layers[0]),COLORS.BLACK)

		print("-------------------------------------")
		print("HIGHEST LAYER:")
		for a in dir(pcap[0].highest_layer):
			print(a)
		# for i, p in enumerate(pcap):
		# 	debug("%i: %s"%(i,p.highest_layer),COLORS.GREEN)
		print("-------------------------------------")
	return outFileName, pcap


def build_windows(features, frameNums):
	full = pds.DataFrame()
	frameIDArr = []

	overlapMustBeFull=True
	useOverlap=True

	print("Building windows from %i packets"%len(features))

	#decide the max number i should be (and step size) depending on if the windows overlap or not.
	nonOverlapCount = len(features)
	overlapCount = len(features) if(not overlapMustBeFull) else (len(features)-windowSize+1)
	maxCount, stepSize = (overlapCount,1) if(useOverlap) else (nonOverlapCount, windowSize)

	print("max count: %i, step size: %i" %(maxCount, stepSize))
	featCount = len(features[0])
	print("Features count: %s"%featCount)
	windowLen = int(maxCount/stepSize)

	fullDict = [None]*windowLen
	debug("Expected full size: %i"%windowLen, COLORS.GREEN)
	for k,i in enumerate(range(0, maxCount, stepSize)): #we can change step to windowsize to do a non-inclusive window building (e.g. 1-5, 5-10, )
		sDebug("Building window number %i"%i,COLORS.ORANGE)
		frames = features[i:i+windowSize]

		frames = [{"frame[%s]-%s"%(n,key):value for key, value in frame.items()} for n, frame in enumerate(frames)]
		window = {"frame ID": k}
		[window.update(frameDF) for frameDF in frames]
		fullDict[k] = window


	full = pds.DataFrame(fullDict)
	debug(len(full),COLORS.BLUE)

	return full


#returns a DataFrame of the features extracted.
#This is what we extract:
#Packet Header Features{
#	ARP* 			[0,1] (I might not implement this)
#	IP				[0,1]
#	ICMP			[0,1]
#	ICMPV6			[0,1]
#	EAPoL*			[0,1] (I am a little confused about this)
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
def extract_features(captures, fast=False):
	def getTimes():
		return round(float128(packet.sniff_timestamp) - firstTime,9)

	def getFrameNumber():
		return packet.number

	def getFrameLength():
		return packet.length

	def Entropy(data):
		# We determine the frequency of each byte
		# in the dataset and if this frequency is not null we use it for the
		# entropy calculation
		dataSize = len(data)
		ent = 0.0

		freq={}
		for c in data:
			freq[c] = freq.get(c, 0)+1

		# a byte can take 256 values from 0 to 255. Here we are looping 256 times
		# to determine if each possible value of a byte is in the dataset
		for key in freq.keys():
			f = float(freq[key])/dataSize
			if f > 0: # to avoid an error for log(0)
				ent = ent + f * math.log(f, LOG_BASE)

		return -ent

	def getInfo():
		headers=["IP","IPV6","ARP","ICMP","ICMPV6","EAPOL","TCP","UDP","HTTP","HTTPS","DHCP","BOOTP","DNS"]
		params = ["Frame Length", "SRC_PORT", "DST_PORT", "TIME", "TCP Window Size", "Payload Length", "Entropy"]

		outParams = {name:np.NAN for name in params}
		outHeader = {name:np.NAN for name in headers}

		for layer in packet.layers:
			name = layer.layer_name.upper()

			if(name in outHeader):
				outHeader[name]=1
			
			if(name=="UDP"):
				outParams["SRC_PORT"]=packet.udp.srcport
				outParams["DST_PORT"]=packet.udp.dstport
			elif(name=="TCP"):
				outParams["SRC_PORT"]=packet.tcp.srcport
				outParams["DST_PORT"]=packet.tcp.dstport
				outParams["TCP Window Size"] = packet.tcp.window_size

		outParams["TIME"] = round(float128(packet.sniff_timestamp) - firstTime,9)				
		outParams["Frame Length"] = packet.length

		if hasattr(packet, "data"):
			if hasattr(packet.data, "data"):
				payload = packet.data.data

				outParams["Payload Length"] = len(payload) if payload else np.NAN
				outParams["Entropy"] = Entropy(packet) if payload else np.NAN

		outDict = {**outParams, **outHeader}
		return outDict

	def decodeipv4():
		return {}
		pktinfos = {"src_addr":np.NAN, "dst_addr":np.NAN, "proto":np.NAN, "proto_name":np.NAN, "src_port":np.NAN, "dst_port":np.NAN}
		ethProto = packet.eth.type.hex_value
		if(ethProto==2048 or ethProto==34525):
			ipPacket = packet.ip if ethProto==2048 else (packet.ipv6 if ethProto==34525 else np.NAN) # should never be none.

			pktinfos['src_addr'] = ipPacket.src
			pktinfos['dst_addr'] = ipPacket.dst
			pktinfos['proto'] = ipPacket.proto if ethProto==2048 else (ipPacket.nxt if ethProto==34525 else np.NAN)
			pktinfos["proto_name"] = packet.transport_layer

			payload = np.NAN
			if pktinfos["proto_name"] == "TCP": #Check for TCP packets
				# payload = packet.data.data
				pktinfos['src_port'] = packet.tcp.srcport
				# print(dir(packet.tcp.dstport))
				pktinfos['dst_port'] = int(packet.tcp.dstport.show)
				pktinfos['TCP_win_size'] = packet.tcp.window_size

			elif pktinfos["proto_name"] == "UDP": #Check for UDP packets
				pktinfos['src_port'] = packet.udp.srcport
				pktinfos['dst_port'] = int(packet.udp.dstport.show)
			elif pktinfos["proto_name"] == "ICMP": #Check for ICMP packets
				pktinfos['src_port'] = 0
				pktinfos['dst_port'] = 0
			else:
				debug("UH OH", COLORS.RED)
				debug(packet,COLORS.BLUE)
				debug(pktinfos,COLORS.BLUE)
				payload = np.NAN
			if hasattr(packet, "data"):

				if hasattr(packet.data, "data"):
					payload = packet.data.data
			return pktinfos, payload
		return pktinfos, np.NAN

	def getPackHeader():
		return {}
		names = ["IP","ICMP","ICMPv6","EAPoL","TCP","UDP","HTTP","HTTPS","DHCP","BOOTP","DNS"]
		#set every value initially to NaN. This allows us to see what is not implemented yet, and what is.
		outDict = {name:np.NAN for name in names}
		ethProto = packet.eth.type.hex_value
		ipProto = int(packet.ip.proto if ethProto==2048 else (packet.ipv6.nxt if ethProto==34525 else -1))

		ipPacket = packet.ip if ethProto==2048 else (packet.ipv6 if ethProto==34525 else None) # should never be none.
		# print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~%s"%ethProto)
		# if(ethProto==2048 or ethProto==34525):
		# 	print(dir(packet.ip))
		# 	print(packet.ip.DATA_LAYER)

		# print(packet)
		# print(dir((packet.tcp if ipProto==6  else (packet.udp if ipProto==17 else -1))))

		srcPort = int(packet.tcp.srcport if ipProto==6  else (packet.udp.srcport if ipProto==17 else -1))
		dstPort = int(packet.tcp.dstport if ipProto==6  else (packet.udp.dstport if ipProto==17 else -1))



		#Network features (IP, EAPol):
		outDict["IP"] = int(ethProto == 2048 or ethProto == 34525)
		outDict["EAPoL"] = int(ethProto == 34958)


		#Transport Features (TCP/UDP/ICMP/ICMPV6):
		outDict["TCP"] = int(ipProto == 6)
		outDict["UDP"] = int(ipProto == 17)

		outDict["ICMP"] = int(ipProto == 1)
		outDict["ICMPv6"] = int(ipProto == 58)
		
		#Application Features (HTTP, DNS, etc.):
		outDict["HTTP"] = int(hasattr(packet, "http") and (srcPort == 80 or dstPort == 80))
		outDict["HTTPS"] = int(srcPort == 443 or dstPort == 443)

		# print(srcPort)
		# print(ipPacket.src)
		# print(ipPacket.dst)

		outDict["DHCP"] = int(hasattr(packet, "dhcp") and ((srcPort == 67 or srcPort == 68) or (dstPort==67 or dstPort==68) and (ipPacket.src=="0.0.0.0" and ipPacket.dst=="255.255.255.255")))
		outDict["BOOTP"] = int((srcPort == 1900 or srcPort == 2869 or srcPort == 5000) or (dstPort == 1900 or dstPort == 2869 or dstPort == 5000))

		outDict["DNS"] = int(hasattr(packet, "dns") and (srcPort == 53 or dstPort == 53))


		return outDict



	#filter outgoing only/incoming etc.
	captures = filter_packets(captures)

	firstTime = float128(captures[0].sniff_timestamp)

	packets = []
	frameNums = []

	for frameID, packet, in enumerate(captures):
		sDebug("PACKET ID: %i"%frameID,COLORS.ORANGE)
		frameDict = getInfo()

		frameNum = getFrameNumber()
		frameNums.append(frameNum)

		packets.append(frameDict)
		# print("------------------")

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



def from_many(files):
	dfOut = pds.DataFrame()
	for fPcap in files:
		pcap = pyshark.FileCapture(fPcap)
		features, frameNums = extract_features(pcap)
		del pcap
		windowArray = build_windows(features, frameNums)
		dfOut = dfOut.append(windowArray)
	return dfOut


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
	# captures = []
	# for packet in pcap:
	# 	captures.append(packet)
	return storage, pcap	
	
if __name__=="__main__":
	storage, captures = main(sys.argv[1:])

	features, frameNums = extract_features(captures)
	# print(features)
	windowArray = build_windows(features, frameNums)

	print("outfile: %s" % storage)
	# print(windowArray)
	windowArray.to_csv(storage)

#-------------------------for testing/debugging------------------------------------
	# for window in windowArrayB:
	# 	window.testing()
#	print('checkpointC')
