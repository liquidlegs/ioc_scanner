from src.vt import VirusTotal, VtApiErr
from src.otx import AlienVault, Ip, Indicator
from src.md import MetaDefenderCloud, ItemType, MdfApiErr
from src.tfx import ThreatFox
from src.shared import Colour as C, get_file_contents, get_items_from_list, Dbg, FeatureList, FeatureState, save_config_file
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF, Item, get_items_from_cmd, validate_domain, validate_hash
import json

metadef_disabled_w = f"{C.f_yellow('Warning')}: MetaDefenderCloud is disabled... Skipping"
vt_disabled_w = f"{C.f_yellow('Warning')}: Virus Total has been disabled... Skipping."
otx_disabled_w = f"{C.f_yellow('Warning')}: AlienVault has been disabled... Skipping."
tfx_disabled_w = f"{C.f_yellow('Warning')}: ThreatFox has been disabled... Skipping."

def check_flags(args):
  '''Function determines if global flags have been specified. If not, behaviour defaults to displaying the quickscan for the corresponding ioc'''
  out = 0

  if args.av == True:
    out += 1
  if args.raw_json == True:
    out += 1
  
  return out


def toggle_features(args):
  dbg = Dbg(args.debug)
  key = args.toggle.lower()
  state = FeatureState.Toggle
  feature = FeatureList.Nan

  if key == "vt":
    dbg.dprint("toggle Virus Total")
    feature = FeatureList.Vt
    state = FeatureState.Toggle
  
  elif key == "otx":
    dbg.dprint("toggle Alien Vault")
    feature = FeatureList.Otx
    state = FeatureState.Toggle
  
  elif key == "md":
    dbg.dprint("toggle MetaDefender")
    feature = FeatureList.Md
    state = FeatureState.Toggle
  
  elif key == "tfx":
    dbg.dprint("toggle Threat Fox")
    feature = FeatureList.Tfx
    state = FeatureState.Toggle
  
  elif key == "warnings":
    dbg.dprint("toggle Warnings")
    feature = FeatureList.Warnings
    state = FeatureState.Toggle
  
  elif key == "enable_all":
    dbg.dprint("enable all features")
    state = FeatureState.Enabled
  
  elif key == "disable_all":
    dbg.dprint("disable all features")
    state = FeatureState.Disabled

  else:
    print(f"{C.f_red('Error')}: unknown feature - {C.fd_cyan(key)}")
    return
  
  dbg.dprint(f"{feature}/{state}")
  save_config_file(args.debug, feature, state)


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


def get_arg_items(args, item: Item):
  dbg = Dbg(args.debug)
  output = []

  # Code block handles file hashes entered in from the commandline.
  if args.iocs != None:
    # First few lines check if the hash(es) are splitable and adds them to the file_hashes list.
    chk = is_arg_list(args.iocs)
    dbg.dprint(f"Are items separated by commas: {chk}")

    if chk == True:
      output.extend(get_items_from_cmd(args.debug, args.iocs, D_LIST, item))

    else:
      results = None
      domain = None
      
      if item == Item.Ip:
        results = validate_ip(args.iocs)
      elif item == Item.Url:
        results = validate_url(args.iocs)
        domain = validate_domain(args.iocs)
      elif item == Item.Hash:
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
    
    if item == Item.Ip:
      output.extend(get_items_from_list(content, Item.Ip))
    if item == Item.Url:
      output.extend(get_items_from_list(content, Item.Url))
      output.extend(get_items_from_list(content, Item.Domain))
    if item == Item.Hash:
      output.extend(get_items_from_list(content, Item.Hash))

  return output


def ioc_args(command: Item, args):
  dbg = Dbg(args.debug)
  items = []

  if command == Item.Ip:
    dbg.dprint("IP parsing")
    items = get_arg_items(args, Item.Ip)
    
    if items != None:
      vt_ip_args(args, items)
      md_ip_args(args, items)    
      otx_ip_args(args, items)
      query_tfx_ioc(args, items)
  
  elif command == Item.Url:
    dbg.dprint("URL parsing")
    items = get_arg_items(args, Item.Url)
    
    if items != None:
      vt_url_args(args, items)
      md_url_args(args, items)
  
  elif command == Item.Hash:
    dbg.dprint("Hash parsing")
    items = get_arg_items(args, Item.Hash)
    
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


def get_url_response_type(url: str) -> Item:
  try:
  
    item_t = url["type"]
    if item_t == "url":
      return Item.Url
    elif item_t == "domain":
      return Item.Domain
  
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

        if item_t == Item.Url:
          urls.append(resp)
        elif item_t == Item.Domain:
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
  dbg = Dbg(args.debug)
  dbg.dprint("calling otx ip")

  otx = AlienVault(args.debug, args.raw_json)
  otx.init()
  
  dbg.dprint(f"Otx has been initalized")
  dbg.dprint(f"OTX disabled: {otx.disabled}")
  dbg.dprint(f"raw_json: {otx.raw_json}")

  if otx.disabled == False:
    responses = []

    if len(ips) < 1:
      print(f"{C.f_red('Error')}: No valid ips to scan")
      return
    
    dbg.dprint(f"Sending {len(ips)} to AlienVault")
    responses.extend(otx.collect_ip_responses(ips))

    if check_flags(args) < 1:
      AlienVault.get_ip_quickscan(responses)    

  else:
    if otx.supress_warnings == False:
      print(otx_disabled_w)


def query_tfx_ioc(args, iocs: list):
  dbg = Dbg(args.debug)
  dbg.dprint("Querying ThreatFox for IOCs")

  tfx = ThreatFox(args.debug, args.raw_json)
  tfx.init()
  
  dbg.dprint(f"ThreatFox has been initalized")
  dbg.dprint(f"ThreatFox disabled: {tfx.disabled}")
  dbg.dprint(f"raw_json: {tfx.raw_json}")

  if tfx.disabled == False:
    responses = []
    
    if len(iocs) < 1:
      dbg.dprint(f"{C.f_red('Error')}: No valid IOCs to scan")
      return
    
    responses.extend(tfx.collect_ioc_responses(iocs))
    
    dbg.dprint(f"Sending {len(iocs)} to ThreatFox")
    ThreatFox.get_ioc_quickscan(responses)
  else:
    if tfx.supress_warnings == False:
      print(tfx_disabled_w)