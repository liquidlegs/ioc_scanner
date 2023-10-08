#!/usr/bin/python3

import argparse
from src.shared import Colour as C
from src.arguments import ioc_args, test_connection, Item

def main():
  parser = argparse.ArgumentParser(description="none")
  parser.add_argument("-t", "--test", action="store_true", help="Test API keys are valid and that we can communicate with outside services")
  parser.add_argument("-o", "--otx-debug", action="store_true", help="Shows raw json response from AlienVault")
  parser.add_argument("-d", "--debug", action="store_true", help="Enables debug messages to be globally displayed")
  parser.add_argument("-r", "--raw-json", action="store_true", help="View the raw json response from the VT API backend.")
  parser.add_argument("--av", action="store_true", help="View the list of vendors that have flagged an ioc.")
  subparsers = parser.add_subparsers(dest="command", help="query the VT api for information about files, hashes, IPs and URLs", required=False)

  file_parser = subparsers.add_parser("hash")
  ip_parser = subparsers.add_parser("ip")
  url_parser = subparsers.add_parser("url")

  file_parser.add_argument("-i", "--iocs", action="store", help="Pass one or multiple hashes into the commandline. Eg: 1,2,3")
  file_parser.add_argument("-f", "--file", action="store", help="Provide a file path to a list of hashes you want to scan.")
  
  ip_parser.add_argument("-i", "--iocs", action="store", help="Pass one or multiple IP addresses into the commandline. Eg: 1,2,3")
  ip_parser.add_argument("-f", "--file", action="store", help="Provide a file path to a list of IP addresses you want to scan.")

  url_parser.add_argument("-i", "--iocs", action="store", help="Pass one or multiple URLs into the commandline. Eg: 1,2,3")
  url_parser.add_argument("-f", "--file", action="store", help="Provide a file path to a list of URLs you want to scan.")
  url_parser.add_argument("-s", "--scan", action="store_true", help="Send urls/domains to be scanned and analyzed by Virus Total")

  args = parser.parse_args()
  if args.command == "hash":
    ioc_args(Item.Hash, args)
  elif args.command == "url":
    ioc_args(Item.Url, args)
  elif args.command == "ip":
    ioc_args(Item.Ip, args)
  elif args.test == True:
    test_connection(args)


if __name__ == '__main__':
  main()