from src.vt import VirusTotal, VtApiErr
from src.avt import AlienVault, Ip, Indicator
from src.md import MetaDenderCloud, NbrItems
from src.shared import Colour as C, get_file_contents, get_items_from_list, Dbg, ArgType
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF, Item, get_items_from_cmd
import json

def check_flags(args):
  '''Function determines if global flags have been specified. If not, behaviour defaults to displaying the quickscan for the corresponding ioc'''
  out = 0

  if args.av == True:
    out += 1
  if args.raw_json == True:
    out += 1
  
  return out


def test_connection(args):
  '''Test communication between each service to determine if configured correctly.'''
  vt = VirusTotal(raw_json=args.raw_json, debug=args.debug)
  vt.init()
  if vt.is_apikey_loaded() == True:
    print(f"{C.f_green('[+]')} Successfully loaded config file")

  out = vt.query_ip_attributes("192.168.1.1")
  err = vt.handle_api_error(out)

  if err == VtApiErr.Nan:
    print(f"{C.f_green('[+]')} Virus Total is correctly configured")

  otx = AlienVault()
  otx.init()
  print(f"{C.f_red('[-]')} AlientVault is not yet implemented")
  
  if otx.is_apikey_loaded() == True:
    print(f"{C.f_yellow('Info')}: Alient API keys are only required viewing OTX premium content via the AlienVault Labs Threat Intelligence Subscription")

  otx_response = otx.get_ip_indicators(Ip.V4, "169.239.129.108", Indicator.general)
  otx_json = json.loads(otx_response)
  out = json.dumps(otx_json, indent=2)
  
  if args.otx_debug == True:
    print(out)


def hash_args(args):
  dbg = Dbg(args.debug)
  dbg.dprint("Hash parsing")

  vt = VirusTotal(raw_json=args.raw_json, debug=args.debug)
  vt.init()

  file_hashes = []
  
  # Code block handles file hashes entered in from the commandline.
  if args.iocs != None:
    # First few lines check if the hash(es) are splitable and adds them to the file_hashes list.
    chk = is_arg_list(args.iocs)
    
    if chk == True:
      file_hashes.extend(get_items_from_cmd(args.iocs, D_LIST, Item.Hash))

    # IF input is not splitable, the entire linel be added to the file_hashes list.
    else:
      result = args.iocs
      if result != None:
        file_hashes.append(result)


  elif args.file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    # All hashes are added to the file_hashes list.
    file_hashes.extend(get_items_from_list(content, Item.Hash))

  vt_hash_args(args, file_hashes)


def url_args(args):
  dbg = Dbg(args.debug)
  dbg.dprint("Url parsing")

  vt = VirusTotal(raw_json=args.raw_json, debug=args.debug)
  vt.init()

  urls = []

  if args.iocs != None:
    # First few lines check if the url(s) are splitable and adds them to the urls list.
    chk = is_arg_list(args.iocs)

    if chk == True:
      urls.extend(get_items_from_cmd(args.iocs, D_LIST, Item.Url))

    # IF input is not splitable, the entire line be added to the urls list.
    else:
      result = validate_url(args.iocs)
      if result != None:
        urls.append(result)


  elif args.file != None:
    # Input is read from a file and a list is returned containing each line.
    content = get_file_contents(args.file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.file, D_LF)

    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    # The process here is the same as the comment above.
    # Only the method to get the data in script is different.
    urls.extend(get_items_from_list(content, Item.Url))
  
  vt_url_args(args, urls)


def ip_args(args):
  dbg = Dbg(args.debug)
  dbg.dprint("IP parsing")

  ips = []
  
  # Split all received ip addresses from the commandline into a list.
  if args.iocs != None:
    chk = is_arg_list(args.iocs)
    
    if chk == True:
      ips.extend(get_items_from_cmd(args.iocs, D_LIST, Item.Ip))

    # Adds a single ip to a list if the array cant be split.
    else:
      result = validate_ip(args.iocs)
      if result != None:
        ips.append(result)

  elif args.file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
      return
    
    # All ips are added to the ip list.
    ips.extend(get_items_from_list(content, Item.Ip))

  vt_ip_args(args, ips)
  md_ip_args(args, ips)


def md_ip_args(args, ips: list):
  md = MetaDenderCloud(debug=args.debug, raw_json=args.raw_json)
  md.init()

  # nbr_items = NbrItems.SINGLE
  # if len(ips) > 1:
  #   nbr_items = NbrItems.BULK

  responses = []

  for i in ips:
    responses.append(md.get_ip_rep(list(i), NbrItems.SINGLE))

  for i in responses:
    print(i)


def vt_hash_args(args, file_hashes: list):
  '''Function sends a list of provided hashes to the Virus Total API'''
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    responses = []
    
    if len(file_hashes) < 1:
        print(f"{C.f_red('Error')}: No valid hashes to scan")
        return

    # Hashes are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_file_responses(file_hashes))

    if args.av == True:
      VirusTotal.get_av_detections(responses, Item.Hash)

    # Displays basic threat score if user enabled quick_scan.
    if check_flags(args) < 1:
      VirusTotal.file_get_quickscan(responses)
  else:
    print(f"{C.f_red('Error')}: Virus Total has been disabled... Skipping.")


def vt_url_args(args, urls: list):
  '''Function sends a list of provided urls/domains to the Virus Total API'''
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    responses = []
    links = []
    
    if len(urls) < 1:
      print(f"{C.f_red('Error')}: No valid urls to scan")
      return

    # Ips are sent to the Virus Total API and each response is stored in a list.
    links.extend(vt.collect_url_reports(urls))

    for link in links:
      resp = vt.get_url_report(link)
      err = vt.handle_api_error(resp)

      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)


    if args.av == True:
      VirusTotal.get_av_detections(responses, Item.Url)

    # Displays basic threat score if user enablled quick_scan.
    if check_flags(args) < 1:
      VirusTotal.url_get_quickscan(responses)
  else:
    print(f"{C.f_red('Error')}: Virus Total has been disabled... Skipping.")


def vt_ip_args(args, ips: list):
  '''Function sends a list of provided IP addresses to the Virus Total API'''
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    responses = []

    if len(ips) < 1:
      print(f"{C.f_red('Error')}: No valid ips to scan")
      return

    # Ips are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_ip_responses(ips))
    
    if args.av == True:
      VirusTotal.get_av_detections(responses, Item.Ip)

    if check_flags(args) < 1:
      VirusTotal.ip_get_quickscan(responses)
  else:
    print(f"{C.f_red('Error')}: Virus Total has been disabled... Skipping.")


def otx_url_args(args, urls: list):
  pass


def otx_hash_args(args, hashes: list):
  pass


def otx_ip_args(args, ips: list):
  pass
