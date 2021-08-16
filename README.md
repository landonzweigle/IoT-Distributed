# IoT-Distributed

## To get the machine learning results:
1. Compile Our Pcaps using compCong.py. See specifics of running compCong.py below.
2. Run the results using ExpRun.py. See specifics of running ExpRun.py below.
3. That's it!

## Code specifics:
### compCong.py:
* compCong is what *Compiles the Conglomerate*. It is multithreaded to be blazing fast.
* It takes a single positional argument which is a path to your directory holding the PCAPS. by default this is [./Captures](https://github.com/landonzweigle/IoT-Distributed/tree/main/Captures)
* **Make sure your capture directory contains every device you would like to get results for**. A device can have multiple PCAPS, just be sure the file starts with a prefix from [this list](https://github.com/landonzweigle/IoT-Distributed/blob/main/Captures/device%20prefix%20list.txt)
### ExpRunner.py:
* ExpRunner is what *Runs Experiments*. 
* It takes a single positional argument which is a path to a conglomerate CSV. If none is provided, it will look for the latest conglomerate under **./windowParsed** (created programmatically with the execution of compCong.py)




#NOTE: The captures directory does not contain all captures. These are just for verification/testing.
