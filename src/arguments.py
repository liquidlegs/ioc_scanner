from src.vt import VirusTotal, VtApiErr
from src.shared import Colour as C, get_file_contents, get_items_from_list
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF, Item, get_items_from_cmd
import json

def file_args(args):
  print("file parser")

  vt = VirusTotal()
  vt.init()

  file_hashes = []
  responses = []
  raw_json = args.raw_json

  if args.hashes != None:
    chk = is_arg_list(args.hashes)
    
    if chk == True:
      file_hashes.extend(get_items_from_cmd(args.hashes, D_LIST, Item.Hash))

    else:
      result = validate_ip(args.hashes)
      if result != None:
        file_hashes.append(result)
  
  
    if len(file_hashes) < 1:
      print(f"{C.f_red('Error')}: No valid hashes to scan")
      return
    
    responses.extend(vt.collect_file_responses(file_hashes, raw_json))

    if args.quick_scan == True:
      VirusTotal.file_get_quickscan(responses)


  elif args.hash_file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.hash_file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.hash_file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    # All ips are added to the ip list.
    file_hashes.extend(get_items_from_list(content, Item.Hash))


    if len(file_hashes) < 1:
      print(f"{C.f_red('Error')}: No valid hashes to scan")
      return

    # Ips are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_file_responses(file_hashes, raw_json))

    # Displays basic threat score if user enablled quick_scan.
    if args.quick_scan == True:
      VirusTotal.file_get_quickscan(responses)



def url_args(args):
  print("url parsing")

  vt = VirusTotal()
  vt.init()

  urls = []
  links = []
  responses = []
  raw_json = args.raw_json

  if args.urls != None:
    chk = is_arg_list(args.urls)

    if chk == True:
      urls.extend(get_items_from_cmd(args.urls, D_LIST, Item.Url))

    else:
      result = validate_url(args.urls)
      if result != None:
        urls.append(result)

      if len(urls) < 1:
        print(f"{C.f_red('Error')}: No valid urls to scan")
        return


    links.extend(vt.collect_url_reports(urls, raw_json))

    for link in links:
      resp = vt.get_url_report(link)
      err = VirusTotal.handle_api_error(resp, raw_json)

      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)

    if args.quick_scan == True:
      VirusTotal.url_get_quickscan(responses)


  elif args.url_file != None:
    content = get_file_contents(args.url_file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.url_file, D_LF)

    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    #
    urls.extend(get_items_from_list(content, Item.Url))  

    if len(urls) < 1:
      print(f"{C.f_red('Error')}: No valid urls to scan")
      return


    # Ips are sent to the Virus Total API and each response is stored in a list.
    links.extend(vt.collect_url_reports(urls, raw_json))


    for link in links:
      resp = vt.get_url_report(link)
      err = VirusTotal.handle_api_error(resp, raw_json)

      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)

    # Displays basic threat score if user enablled quick_scan.
    if args.quick_scan == True:
      VirusTotal.url_get_quickscan(responses)


def ip_args(args):
  print("ip parsing")

  vt = VirusTotal()
  vt.init()
  
  ips = []
  responses = []
  raw_json = args.raw_json

  # Split all received ip addresses from the commandline into a list.
  if args.ips != None:
    chk = is_arg_list(args.ips)
    
    if chk == True:
      ips.extend(get_items_from_cmd(args.ips, D_LIST, Item.Ip))

    # Adds a single ip to a list if the array cant be split.
    else:
      result = validate_ip(args.ips)
      if result != None:
        ips.append(result)
  
  
    if len(ips) < 1:
      print(f"{C.f_red('Error')}: No valid ips to scan")
      return
    
    responses.extend(vt.collect_ip_responses(ips, raw_json))

    if args.quick_scan == True:
      VirusTotal.ip_get_quickscan(responses)

  # Code block executes if the has specified a file containing ips to scan.
  elif args.ip_file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.ip_file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.ip_file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    # All ips are added to the ip list.
    ips.extend(get_items_from_list(content, Item.Ip))


    if len(ips) < 1:
      print(f"{C.f_red('Error')}: No valid ips to scan")
      return

    # Ips are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_ip_responses(ips, raw_json))

    # Displays basic threat score if user enablled quick_scan.
    if args.quick_scan == True:
      VirusTotal.ip_get_quickscan(responses)