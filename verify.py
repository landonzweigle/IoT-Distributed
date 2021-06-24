import os, ProcPackIMP as proc

CapDir = "./Captures/"

class test:
	passed = False
	name = ""

	def __init__(self, name, passed):
		self.name = name
		self.passed = passed

def main():
	validRuns = []
	for f in os.listdir(CapDir):
		if(f.split(".")[-1]=="pcap"):
			validRuns.append(f.split(".")[0])
	runTests(validRuns)

def runTests(validRuns):
	tests = []

	for toRun in validRuns:
		print("Running %s" % toRun)
		print("-----------------------------------------------------------")
		passed = True

		try:
			proc.main(toRun)
		except:
			passed = False

		nClass = test(toRun, passed)
		tests.append(nClass)
		print("-----------------------------------------------------------")

	print("\n----------------Tests Complete----------------")

	for strRes in pPrintTests(tests):
		print(strRes)


def pPrintTests(tests):
	_cRed = "\033[0;31m"
	_cGreen = "\033[0;32m"
	_cERR = "\033[1;31m"
	_cEOC = "\033[0m"

	passedKey = ("%sPASSED%s" % (_cGreen,_cEOC))
	failedKey = ("%sFAILED%s" % (_cRed,_cEOC))
	errordKey = ("%sERRORED%s" % (_cERR,_cEOC))


	largestKey = 0
	for res in tests:
		sKey = len(res.name)
		if sKey > largestKey:
			largestKey = sKey


	allPass = True
	failed = []
	for result in tests:
		spacing = " " * (largestKey - len(result.name))

		toYield  = result.name + spacing + " |  " + (passedKey if result.passed else failedKey)

		if(not result.passed):
			allPass = False
			failed.append(toYield)

		yield toYield


	resStr = "All Tests Pass" if allPass else "Test(s) failed"
	color = _cGreen if allPass else _cRed
	yield "\n----------------" + color + resStr + _cEOC + "----------------"
	for fail in failed:
		yield fail

if __name__ == "__main__":
	print("Running Main")
	main()
