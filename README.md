# virus_total_api
using the api from virus total for scanning hashes

#Information
NOTE1: The script wrote in python.

NOTE2: You need your own API key to use this tool.

Original Script Author: uriar
usage: hash_checker.py [-h] [-i INPUT] -o OUTPUT [-H HASH] -k KEY [-u]

Query hashes against Virus Total.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input File Location EX: /Somewhere/input.txt
  -o OUTPUT, --output OUTPUT
                        Output File Location EX: /Somewhere/output.txt
  -H HASH, --hash HASH  Single Hash EX: d41d8cd98f00b204e9800998ecf8427e
  -k KEY, --key KEY     API Key EX: ASDFADSFDSFASDFADSFDSFADSF
  -u, --unlimited       Changes the 26 second sleep timer to 1.
