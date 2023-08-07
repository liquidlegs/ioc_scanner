from src.vt import VirusTotal, VtApiErr
from src.shared import Colour as C
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF
import json, os, platform

def file_args(args):
  print("file parser")

  vt = VirusTotal()
  vt.init()

  if len(args.hashes) > 0:
    hash = args.hashes

    response = vt.query_file_attributes(hash)
    if args.rawjson == True:
      print(response)
      return

    VirusTotal.handle_api_error(response)


def url_args(args):
  print("url parsing")

  vt = VirusTotal()
  vt.init()

  if len(args.urls) > 0:
    address = validate_url(args.urls)

    if address == None:
      print(f"{C.red('Error')}: Invalid url")
      return
    
    response = vt.query_url_attributes(address)
    if args.rawjson == True:
      print(response)
      return
    
    VirusTotal.handle_api_error(response)

# Splits ip address received from the commandline and returns them as a list.
def get_ips_from_cmd(istring: str, delim: str) -> list[str]:
  out = []
  temp_ips = istring.split(delim)

  for ip in temp_ips:
    result = validate_ip(ip)
    
    if result != None:
      out.append(result)

  return out


# Splits ip addresses contained in a string, like read from a file and returns it as a list.
def get_ips_from_list(content: list[str]) -> list[str]:
  out = []
  
  for line in content:
    ip = validate_ip(line)
    
    if ip != None:
      out.append(ip)

  return out


def get_file_contents(filepath: str, delim: str) -> list[str]:
  path = ""
  slash = ""

  # Get the correct slash for the correct system
  if platform.system == "windows":
    slash = "\\"
  else:
    slash = "/"
  
  # Fix the path if not absolute
  if os.path.exists(filepath):
    if os.path.abspath(filepath) == False:
      path = f"{os.getcwd}{slash}{filepath}"
    else:
      path = filepath

  # Read the file into a buffer and split each line by the specified delimiter
  buffer = ""
  with open(path, "r") as f:
    buffer = f.read()

  output = buffer.split(delim)
  return output


def ip_args(args):
  print("ip parsing")

  vt = VirusTotal()
  vt.init()
  
  ips = []
  responses = []
  raw_json = args.rawjson

  if args.ips != None:
    chk = is_arg_list(args.ips)
    
    if chk == True:
      ips.extend(get_ips_from_cmd(args.ips, D_LIST))
    
    else:
      result = validate_ip(args.ips)
      if result != None:
        ips.append(result)
  
  
  elif args.ip_file != None:
    content = get_file_contents(args.ip_file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.ip_file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    ips.extend(get_ips_from_list(content))


  if len(ips) < 1:
    print(f"{C.f_red('Error')}: No valid ips to scan")
    return


  for ip in ips:
    resp = vt.query_ip_attributes(ip)
    err = VirusTotal.handle_api_error(resp, raw_json)

    if err == VtApiErr.Nan:
      data = json.loads(resp)
      responses.append(data)

  if args.quick_scan == True:
    VirusTotal.ip_get_quickscan(responses)