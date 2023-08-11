import argparse
from src.shared import Colour as C
from src.arguments import file_args, url_args, ip_args, test_connection

def main():
  parser = argparse.ArgumentParser(description="none")
  parser.add_argument("-t", "--test", action="store_true", help="Test API keys are valid and that we can communicate with outside services")
  parser.add_argument("-o", "--otx-debug", action="store_true", help="Shows raw json response from AlienVault")
  subparsers = parser.add_subparsers(dest="command", help="query the VT api information about files, hashes, IPs and URLs", required=False)

  file_parser = subparsers.add_parser("file")
  ip_parser = subparsers.add_parser("ip")
  url_parser = subparsers.add_parser("url")

  file_parser.add_argument("-H", "--hashes", action="store", help="Pass one or multiple hashes into the commandline. Eg: 1,2,3")
  file_parser.add_argument("--hash-file", action="store", help="Provide a file path to a list of hashes you want to scan.")
  file_parser.add_argument("-a", "--av", action="store_true", help="View the list of vendors that have flagged an ioc. [TODO]")
  file_parser.add_argument("-q", "--quick-scan", action="store_true", help="View how many vendors have deemed the ioc to be malicious, harmelsss, suspicious and undetected.")
  file_parser.add_argument("-r", "--raw-json", action="store_true", help="View the raw json response from the VT API backend.")
  
  ip_parser.add_argument("-i", "--ips", action="store", help="Pass one or multiple IP addresses into the commandline. Eg: 1,2,3")
  ip_parser.add_argument("--ip-file", action="store", help="Provide a file path to a list of IP addresses you want to scan.")
  ip_parser.add_argument("--av", action="store_true", help="View the list of vendors that have flagged an ioc. [TODO]")
  ip_parser.add_argument("-q", "--quick-scan", action="store_true", help="View how many vendors have deemed the ioc to be malicious, harmelsss, suspicious and undetected.")
  ip_parser.add_argument("-r", "--raw-json", action="store_true")

  url_parser.add_argument("-u", "--urls", action="store", help="Pass one or multiple URLs into the commandline. Eg: 1,2,3")
  url_parser.add_argument("--url-file", action="store", help="Provide a file path to a list of URLs you want to scan.")
  url_parser.add_argument("--av", action="store_true", help="View the list of vendors that have flagged an ioc. [TODO]")
  url_parser.add_argument("-q", "--quick-scan", action="store_true", help="View how many vendors have deemed the ioc to be malicious, harmelsss, suspicious and undetected.")
  url_parser.add_argument("-r", "--raw-json", action="store_true", help="View the raw json response from the VT API backend.")

  args = parser.parse_args()
  if args.command == "file":
    file_args(args)
  elif args.command == "url":
    url_args(args)
  elif args.command == "ip":
    ip_args(args)
  elif args.test == True:
    test_connection(args)

  pass

if __name__ == '__main__':
  main()