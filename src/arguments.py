from src.vt import VirusTotal, VtApiErr
from src.avt import AlienVault, Ip, Indicator
from src.md import MetaDefenderCloud, ItemType, MdfApiErr
from src.shared import Colour as C, get_file_contents, get_items_from_list, Dbg, ArgType
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF, Item, get_items_from_cmd, validate_domain, validate_hash
import json

metadef_disabled_w = f"{C.f_yellow('Warning')}: MetaDefenderCloud is disabled... Skipping"
vt_disabled_w = f"{C.f_red('Error')}: Virus Total has been disabled... Skipping."

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
  if vt.is_apikey_loaded() == True and vt.disabled == False:
    print(f"{C.f_green('[+]')} Successfully found the Virus Total API key")

    out = vt.query_ip_attributes("192.168.1.1")
    err = vt.handle_api_error(out)

    if err == VtApiErr.Nan:
      print(f"{C.f_green('[+]')} Virus Total is correctly configured")

  otx = AlienVault()
  otx.init()
  
  if otx.disabled == False:
    print(f"{C.f_red('[-]')} AlientVault is not yet implemented")
    otx_response = otx.get_ip_indicators(Ip.V4, "169.239.129.108", Indicator.general)
    otx_json = json.loads(otx_response)
    out = json.dumps(otx_json, indent=2)
    
    if args.otx_debug == True:
      print(out)

  md = MetaDefenderCloud()
  md.init()
  mapikey_info = ""
  
  if md.is_apikey_loaded() == True and md.disabled == False:
    print(f"{C.f_green('[+]')} Successfully found the MetaDefenderCloud API key")

    mapikey_info = md.get_apikey_info()
    print(f"metadefender enabled: {md.disabled}")
    MetaDefenderCloud.show_apikey_info(mapikey_info)


# def hash_args(args):
#   dbg = Dbg(args.debug)
#   dbg.dprint("Hash parsing")

#   # vt = VirusTotal(raw_json=args.raw_json, debug=args.debug)
#   # vt.init()

#   file_hashes = []
  
#   # Code block handles file hashes entered in from the commandline.
#   if args.iocs != None:
#     # First few lines check if the hash(es) are splitable and adds them to the file_hashes list.
#     chk = is_arg_list(args.iocs)
    
#     if chk == True:
#       file_hashes.extend(get_items_from_cmd(args.iocs, D_LIST, Item.Hash))

#     # IF input is not splitable, the entire linel be added to the file_hashes list.
#     else:
#       result = args.iocs
#       if result != None:
#         file_hashes.append(result)


#   elif args.file != None:
#     # Attempts to read the text file and split each line with CRLF or LF.
#     content = get_file_contents(args.file, D_CRLF)
#     if len(content) < 2:
#       content = get_file_contents(args.file, D_LF)
    
#     if len(content) < 2:
#       print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
#       return
    
#     # All hashes are added to the file_hashes list.
#     file_hashes.extend(get_items_from_list(content, Item.Hash))

#   vt_hash_args(args, file_hashes)
#   md_hash_args(args, file_hashes)


# def url_args(args):
#   dbg = Dbg(args.debug)
#   dbg.dprint("Url parsing")

#   # vt = VirusTotal(raw_json=args.raw_json, debug=args.debug)
#   # vt.init()

#   urls = []

#   if args.iocs != None:
#     # First few lines check if the url(s) are splitable and adds them to the urls list.
#     chk = is_arg_list(args.iocs)

#     if chk == True:
#       urls.extend(get_items_from_cmd(args.iocs, D_LIST, Item.Url))

#     # IF input is not splitable, the entire line be added to the urls list.
#     else:
#       result = validate_url(args.iocs)
#       if result != None:
#         urls.append(result)


#   elif args.file != None:
#     # Input is read from a file and a list is returned containing each line.
#     content = get_file_contents(args.file, D_CRLF)
#     if len(content) < 2:
#       content = get_file_contents(args.file, D_LF)

#     if len(content) < 2:
#       print(f"{C.f_red('Error')}: unable to split each line by CRLF ('\r\n') or LF ('\n')")
#       return
    
#     # The process here is the same as the comment above.
#     # Only the method to get the data in script is different.
#     urls.extend(get_items_from_list(content, Item.Url))
  
#   vt_url_args(args, urls)
#   md_url_args(args, urls)


def get_arg_items(args, item: ItemType):
  output = []

  # Code block handles file hashes entered in from the commandline.
  if args.iocs != None:
    # First few lines check if the hash(es) are splitable and adds them to the file_hashes list.
    chk = is_arg_list(args.iocs)
    
    if chk == True:
      output.extend(get_items_from_cmd(args.iocs, D_LIST, item))

    else:
      results = None
      domain = None
      
      if item == ItemType.IP:
        results = validate_ip(args.iocs)
      elif item == ItemType.URL:
        results = validate_url(args.iocs)
        domain = validate_domain(args.iocs)
      elif item == ItemType.HASH:
        results = validate_hash(args.iocs)

      if results != None:
        output.append(results)

      if domain != None:
        output.append(domain)
  

  elif args.file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_yellow('Warning')}: unable to split each line by CRLF ('\\r\\n') or LF ('\\n')")
    
    if item == ItemType.IP:
      output.extend(get_items_from_list(content, Item.Ip))
    if item == ItemType.URL:
      output.extend(get_items_from_list(content, Item.Url))
      output.extend(get_items_from_list(content, Item.Domain))
    if item == ItemType.HASH:
      output.extend(get_items_from_list(content, Item.Hash))

  return output


def ioc_args(command: ItemType, args):
  dbg = Dbg(args.debug)
  items = []

  if command == ItemType.IP:
    dbg.dprint("IP parsing")
    items = get_arg_items(args, ItemType.IP)
    
    if items != None:
      vt_ip_args(args, items)
      md_ip_args(args, items)    
  
  elif command == ItemType.URL:
    dbg.dprint("URL parsing")
    items = get_arg_items(args, ItemType.URL)
    
    if items != None:
      vt_url_args(args, items)
      md_url_args(args, items)
  
  elif command == ItemType.HASH:
    dbg.dprint("Hash parsing")
    items = get_arg_items(args, ItemType.HASH)
    
    if items != None:
      vt_hash_args(args, items)
      md_hash_args(args, items)


def md_ip_args(args, ips: list):
  md = MetaDefenderCloud(debug=args.debug, raw_json=args.raw_json)
  md.init()

  output = ""

  if md.disabled == False:
    if len(ips) == 1:
      output = md.get_ip_rep(ips[0])
    elif len(ips) > 1:
      output = md.get_ip_rep_bulk(ips)

    if args.raw_json == True:
      print(output[0])

    err = md.handle_api_error(output[0])
    if err == MdfApiErr.Nan:
      MetaDefenderCloud.get_quickscan_ip(output[0], output[1])
  else:
    if md.supress_warnings == False:
      print(metadef_disabled_w)


def md_hash_args(args, hashes: list):
  md = MetaDefenderCloud(debug=args.debug, raw_json=args.raw_json)
  md.init()

  output = ""

  if md.disabled == False:
    if len(hashes) == 1:
      output = md.get_hash_rep(hashes[0])
    elif len(hashes) > 1:
      output = md.get_hash_rep_bulk(hashes)

    MetaDefenderCloud.get_quickscan_hash(output[0], output[1])
  else:
    if md.supress_warnings == False:
      print(metadef_disabled_w)


def md_url_args(args, urls: list):
  md = MetaDefenderCloud(debug=args.debug, raw_json=args.raw_json)
  md.init()

  output = ""

  if md.disabled == False:
    if len(urls) == 1:
      output = md.get_url_rep(urls[0], ItemType.URL)
    elif len(urls) > 1:
      output = md.get_url_rep_bulk(urls, ItemType.URL)

    print(output[0])
  else:
    if md.supress_warnings == False:
      print(metadef_disabled_w)


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
    if vt.supress_warnings == False:
      print(vt_disabled_w)


def get_url_response_type(url: str) -> ItemType:
  try:
  
    item_t = url["type"]
    if item_t == "url":
      return ItemType.URL
    elif item_t == "domain":
      return ItemType.DOMAIN
  
  except KeyError:
    return None

  return None


def sort_urls_and_domains(responses: list, debug=False) -> [list, list]:
  urls = []
  domains = []
  
  try:
    for resp in responses:
      data = resp["data"]

      for i in data:
        item_t = get_url_response_type(i)
        if debug == True:
          Dbg._dprint(f"JSON response type is {item_t}")

        if item_t == ItemType.URL:
          urls.append(resp)
        elif item_t == ItemType.DOMAIN:
          domains.append(resp)

  except KeyError:
    pass
  
  return [urls, domains]


def vt_url_args(args, urls: list):
  '''Function sends a list of provided urls/domains to the Virus Total API'''
  dbg = Dbg(args.debug)
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    responses = []
    links = []

    h_urls = []
    h_domains = []
    
    if len(urls) < 1:
      print(f"{C.f_red('Error')}: No valid urls to scan")
      return

    if args.scan == True:
      # Ips are sent to the Virus Total API and each response is stored in a list.
      example_command_1 = "ioc_scanner.py url -i http://yourUrl.com"
      example_command_2 = "ioc_scanner.py url -f pathToYourFile.txt"
      cmd = ""

      links.extend(vt.collect_url_report_links(urls))
      print(f"{C.f_green('[+]')} Successfully uploaded {C.fd_cyan(str(len(links)))} urls to be scanned Virus Total")

      if args.iocs != None:
        cmd = example_command_1
      elif args.file != None:
        cmd = example_command_2

      print(f"{C.f_yellow('Info')}: You can view the results of analysis with the '{C.fd_cyan(cmd)}'")
      if args.debug == True:
        for i in links:
          dbg.dprint(i)
      
      return

    else:
      responses.extend(vt.collect_url_responses(urls))
      resp_pair = sort_urls_and_domains(responses, args.debug)

      dbg.dprint(f"Responses: {len(responses)}")
      dbg.dprint(f"urls: {len(resp_pair[0])}")
      dbg.dprint(f"domains: {len(resp_pair[1])}")

      h_urls = resp_pair[0]
      h_domains = resp_pair[1]


    if args.av == True:
      VirusTotal.get_av_detections(responses, Item.Url)

    # Displays basic threat score if user enablled quick_scan.
    if check_flags(args) < 1:
      if len(h_urls) > 0:
        VirusTotal.url_get_vtintel_quickscan(h_urls)
      if len(h_domains) > 0:
        VirusTotal.domain_get_vtintel_quickscan(h_domains)
  else:
    if vt.supress_warnings == False:
      print(vt_disabled_w)


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
    if vt.supress_warnings == False:
      print(vt_disabled_w)


def otx_url_args(args, urls: list):
  pass


def otx_hash_args(args, hashes: list):
  pass


def otx_ip_args(args, ips: list):
  pass
