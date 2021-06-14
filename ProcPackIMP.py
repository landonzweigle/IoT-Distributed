
import sys, getopt, datetime, time, os
import dpkt
import pandas as pds, pyshark as psk

#Written by Landon Zweigle

# logarithm Base (default = 2)
LOG_BASE = 2 # math.e
##sys.setdefaultencoding('utf8')
entropy = 0
leng = 0

capDir = "./Captures/"


##This method has two parts
## First part allows for capture of packets on a specified ip address from command line
## Second part processes the captured packets-- this is what you are intersted.
## For  now, you can comment out the first few pieces of the code and use the remaining parts.
def Collect():
	ip = ""
	count = 100
	inFile =""
	outFile =""
	inter =""

	if(len(sys.argv) != 2):
		raise Excpetion("One (or more) arguments must be specified. The first arguement referse to the device being processed (for accessing arg0.pcap/csv)")

	try:
		try: ##gather pcap file name and storage file name
			opts, args = getopt.getopt(sys.argv[1:],"hi:c:",["ipaddress=","pcount=="])
		except getopt.GetoptError:
			sys.exit(1)
		for opt, arg in opts:
			if opt in ("-i","--ipaddress"):
				ip = arg
			elif opt in ("-c","--pcount"):
				count = arg
			else:
				print ("input error!")
				sys.exit(1)


		inFile = capDir + sys.argv[1] + '.pcap'
		storageName = capDir + sys.argv[1] + '.csv'
		pcap = psk.FileCapture(inFile)

		print('Capture file is [' + inFile + ']')
		print('Storage File is [' + storageName + ']')
		print('--------------------------')
		print('Starting Packet Header Parse...')

		os.system('touch ' + storageName)
		os.system('tshark -r ' + inFile + ' -T fields -e frame.number -e frame.protocols -e frame.len -e frame.packet_flags -e frame.time -e frame.time_relative -e eth.src -e eth.dst -e ip.src -e ip.dst -e ip.version -e ip.proto -e ip.ttl -e ip.hdr_len -e ip.len -e ip.id -e ip.flags -e ip.frag_offset -e ip.checksum -e tcp.seq -e tcp.ack -e tcp.srcport -e tcp.dstport -e tcp.hdr_len -e tcp.len -e tcp.flags -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.checksum -e tcp.window_size_value -e http.request.version -E header=y -E separator=, -E quote=d -E occurrence=f > ' + storageName)

		print('Header Parse Finished...')
		print('--------------------------')
		print('Calculating Packet Entropy')

		#load the parsed header into a DataFrame
		df = pds.read_csv(storageName, index_col=False)#.dropna(axis=1, how="all") #right now I dont know if I should keep the NA columns.

		#create the out DataFrame (csv)
		outDF = pds.DataFrame(columns=list(df.columns.values)+["Payload Entropy", "Payload Length"])
		print(df)
		print(outDF)

		print()

		#iterate over every packet in the dataframe df. Analyse it, and append the result to the output DataFrame (outdf).
		res = df.apply(tApply, axis=1, pcap=pcap)
		print(res)

		exit()

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------#
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------#

		# open csv file and add "payload entropy" and "payload length" to columns

#		data = []
#		try:
#			row0 = csvR.next()
#			row0.append('Payload Entropy')
#			row0.append('Payload Length')
#			data.append(row0)
#		except StopIteration:
#			print ('No Rows')
#		except:
#			print ('Something else went wrong')

		# make pcapObject to parse the pcap file
#		p = pcap.pcapObject()
#		p.open_offline(inFile)
		try:
			for item in csvR:
				p.dispatch(1, analysepacket)
				item.append(entropy)
				item.append(leng)
				data.append(item)

		except KeyboardInterrupt:
			print ('interrupt')
		csvFile = open(storageName, 'w')
		csvW = csv.writer(csvFile)
		csvW.writerows(data)

		print('Finished Calcualting Packet Entropy')
		print('--------------------------')
		print('Sending Data to Storage')
		print('--------------------------')
		##os.system('scp ./' + storageName + ' ./' + inFile + ' jordantp@tokyo.cs.colostate.edu:/s/fir/e/nobackup/nuclear_iot/IOT')
		print('Finished Sending Data to Storage')
		print('--------------------------')
		sys.exit()
            
	except KeyboardInterrupt:
		print("Closing Program...")
		sys.exit()

def tApply(d, pcap):
#	if not pcap and not d:
#		return

	index = d.name
	print("ID: %s" % (index))
	packet = pcap[index]

	print(packet)

	print("type: " + packet.eth.type.showname_value.split(" ",1)[0])
	ipType = packet.eth.type.showname_value.split(" ",1)[0]

	#check if it is ipv4. This is essentially what extractpayload did.
	if(ipType == "IPv4"):
		print(dir(packet.ip))
		pktinfos, payload = decodeipv4(packet)

		if(pktinfos and payload):
			entropy = Entropy(payload)
			leng = len(payload)
			
			return leng






##This part is where packet processing happens
def decodeipv4(packet):
	pktinfos = {"src_addr":None, "dst_addr":None, "proto":None, "proto_name":None, "src_port":None, "dst_port":None}
	pktinfos['src_addr'] = packet.ip.src
	pktinfos['dst_addr'] = packet.ip.dst
	pktinfos['proto'] = packet.ip.proto
	pktinfos["proto_name"] = packet.transport_layer
	payload = packet.data.data

	if pktinfos["proto_name"] == "TCP": #Check for TCP packets
		pktinfos['src_port'] = packet.tcp.srcport
		pktinfos['dst_port'] = packet.tcp.dstport

	elif pktinfos["proto_name"] == "UDP": #Check for UDP packets
		pktinfos['src_port'] = packet.udp.srcport
		pktinfos['dst_port'] = packet.udp.dstport

	elif pktinfos["proto_name"] == "ICMP": #Check for ICMP packets
		pktinfos['src_port'] = 0
		pktinfos['dst_port'] = 0

	else:
		pktinfos,payload=None, None

	return pktinfos, payload


def Entropy(data):
   # We determine the frequency of each byte
   # in the dataset and if this frequency is not null we use it for the
   # entropy calculation
	dataSize = len(data)
	ent = 0.0

	freq={}
	for c in data:
		if freq.has_key(c):
			freq[c] += 1
		else:
			freq[c] = 1

   # a byte can take 256 values from 0 to 255. Here we are looping 256 times
   # to determine if each possible value of a byte is in the dataset
	for key in freq.keys():
		f = float(freq[key])/dataSize
		if f > 0: # to avoid an error for log(0)
			ent = ent + f * math.log(f, LOG_BASE)

	return -ent



##This you can change or just change the Collect method to process a pcap file of your choice. Use Linux based python interpreter as it will have the pcap file.
def main():
	Collect()

if __name__ == "__main__":
	print("Running Main")
	main()
