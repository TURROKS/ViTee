# ViTee  
**ViTee is tool based in Python that allows you to leverage Virus Total's API**  
  
ViTee allows you to provide a single source file with your IOCs and get a report for the below    
 * URLs  
 * IPs  
 * Domains  
 * Hashes  
     
I recommend creating a Virtual Environment (venv) to avoid changing your base Python's setup.  [Instructions here](https://docs.python.org/3/library/venv.html)
  
You can install the required modules once the venv is ready and you have activated it.  
  
go to the root of the project and run

`$ pip install -r requirements.txt`
  
With the required modules installed you can now use the script to generate your reports.  
  
`python vitee.py -i source.txt -o dest -m 1`
  
Once you run the command you will see the following window, which details the IOCs to be queried after removing duplicates.  
  
![Startup](https://github.com/TURROKS/ViTee/blob/master/misc/startup.png)  
  
Output Example  
  
![Results](https://github.com/TURROKS/ViTee/blob/master/misc/results.PNG)  
  
You can run python vitee.py -h to get the help menu  
  
**required arguments:**
  
 - -i, --infile  Input File (takes txt and csv) -o, --outfile Output File (returns xlsx, there's no need to add .xlsx extension to the file name)  

**optional arguments:**
  
 - -h, --help    show this help message and exit -a, --api     Manually Enter API -m, --membership  Type 1=Free(Default), 2=Paid -u, --update  Update API  

*Troubleshooting*  
  
If you face issues installing the iocextract library on Windows you might need to install C++ 14, this is usually installed with Visual Studio but if you don't want to install the tool you can download and install the required libraries from [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe.)  
  
Enjoy the tool