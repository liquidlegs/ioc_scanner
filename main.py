import argparse
from src.shared import Colour as C
from src.arguments import file_args, url_args, ip_args

def main():
  parser = argparse.ArgumentParser(description="none")
  subparsers = parser.add_subparsers(dest="command", help="query the VT api information about files, hashes, IPs and URLs", required=True)

  file_parser = subparsers.add_parser("file")
  ip_parser = subparsers.add_parser("ip")
  url_parser = subparsers.add_parser("url")

  file_parser.add_argument("-H", "--hashes", action="store")
  file_parser.add_argument("--hash-file", action="store")
  file_parser.add_argument("-a", "--av", action="store_true")
  file_parser.add_argument("-q", "--quick-scan", action="store_true")
  file_parser.add_argument("-r", "--raw-json", action="store_true")
  
  ip_parser.add_argument("-i", "--ips", action="store")
  ip_parser.add_argument("--ip-file", action="store")
  ip_parser.add_argument("--av", action="store_true")
  ip_parser.add_argument("-q", "--quick-scan", action="store_true")
  ip_parser.add_argument("-r", "--raw-json", action="store_true")

  url_parser.add_argument("-u", "--urls", action="store")
  url_parser.add_argument("--url-file", action="store")
  url_parser.add_argument("--av", action="store_true")
  url_parser.add_argument("-q", "--quick-scan", action="store_true")
  url_parser.add_argument("-r", "--raw-json", action="store_true")

  args = parser.parse_args()
  if args.command == "file":
    file_args(args)
  elif args.command == "url":
    url_args(args)
  elif args.command == "ip":
    ip_args(args)

  pass

if __name__ == '__main__':
  main()