# ViTee  
**ViTee is tool based in Python that allows you to leverage Virus Total's API**  
  
ViTee allows you to provide a single source file with your IOCs, it **automatically extracts and parses** the following types of IOCs

 * URLs  
 * IPs  
 * Domains  
 * Hashes  

It then checks each unique IOC against VirusTotal and generates a report with unique tabs per IOC type.

I recommend creating a Virtual Environment (venv) to avoid changing your base Python's setup.  [Instructions here](https://docs.python.org/3/library/venv.html)
 
### Installation

You can install the required modules once the venv is ready, and you have activated it.  
  
go to the root of the project and run

`$ pip install -r requirements.txt`


### Running the scripts

With the required modules installed you can now use the script to generate your reports.  
  
`python vitee.py -i source.txt -o dest -m 1 -a <YOUR API>`
  
Once you run the command you will see the following window, which details the IOCs to be queried after removing duplicates.  
  
![Startup](https://github.com/TURROKS/ViTee/blob/master/docs/misc/startup.png)  
  
Output Example  

**CLI**

![Results](https://github.com/TURROKS/ViTee/blob/master/docs/misc/results.PNG)  

**REPORT**

1. Domains

![Domains](https://github.com/TURROKS/ViTee/blob/master/docs/misc/domains.png)

2. IP Addresses

![IPs](https://github.com/TURROKS/ViTee/blob/master/docs/misc/ips.png)

3. Hashes

![Hashes](https://github.com/TURROKS/ViTee/blob/master/docs/misc/hashes.png)

You can save your API in the config by running

`python vitee.py -u YOUR_API_KEY`
  

### Arguments

You can run python vitee.py -h to get the help menu  
  
**Required**
 
| Flag         | Description                                                                         |
|--------------|-------------------------------------------------------------------------------------|
| -i, --file   | inputs File -takes txt and csv                                                      |
| -o, --output | Output File - returns xlsx, there's no need to add .xlsx extension to the file name |
| -a, --api    | Manually Enter API  Unless you save your Key (See optional arguments)               |

**Optional**
  
| Flag                  | Description                     |
|-----------------------|---------------------------------|
 | -h, --help            | show this help message and exit |
 | -m, --membership type | 1=Free **Default**, 2=Paid      |
 | -u, --update          | Update API                      |

*Troubleshooting*  
  
If you face issues installing the iocextract library on Windows you might need to install C++ 14, this is usually installed with Visual Studio but if you don't want to install the tool you can download and install the required libraries from [Visual C++ 2015 Build Tools](http://go.microsoft.com/fwlink/?LinkId=691126&fixForIE=.exe.)  
  
Enjoy the tool
