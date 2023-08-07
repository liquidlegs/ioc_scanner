from vt import VirusTotal, VtApiErr
from shared import Colour as C
from shared import validate_ip, validate_url, is_arg_list, D_LIST
import json

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


def ip_args(args):
  print("ip parsing")

  vt = VirusTotal()
  vt.init()
  
  ips = []
  responses = []
  raw_json = args.rawjson

  chk = is_arg_list(args.ips)
  if chk == True:
    temp_ips = args.ips.split(D_LIST)

    for ip in temp_ips:
      result = validate_ip(ip)
      
      if result != None:
        ips.append(result)

  else:
    result = validate_ip(args.ips)
    if result != None:
      ips.append(result)
  
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