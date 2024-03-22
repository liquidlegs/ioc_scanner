from src.vt import VirusTotal, VtApiErr
from src.otx import AlienVault, Ip, Indicator, IndicatorType
from src.tfx import ThreatFox, QueryType
from prettytable.colortable import ColorTable
from src.shared import Colour as C, get_file_contents, get_items_from_list, Dbg, FeatureList, FeatureState, save_config_file, load_config, check_json_error
from src.shared import validate_ip, validate_url, is_arg_list, D_LIST, D_CRLF, D_LF, Item, get_items_from_cmd, validate_domain, validate_hash

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
  '''Function sets a few enums that control how and what features will be disbaled or enabled in the config file.'''

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


def get_arg_items(args, item: Item):
  dbg = Dbg(args.debug)
  output = {
    "ioc": [],
    "domain": []
  }

  # Code block handles file hashes entered in from the commandline.
  if args.iocs != None:
    # First few lines check if the hash(es) are splitable and adds them to the file_hashes list.
    chk = is_arg_list(args.iocs)
    dbg.dprint(f"Are items separated by commas: {chk}")

    if chk == True:
      output = get_items_from_cmd(args.debug, args.iocs, D_LIST, item)

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
        output["ioc"].append(results)

      if domain != None:
        output["domain"].append(domain)
  

  elif args.file != None:
    # Attempts to read the text file and split each line with CRLF or LF.
    content = get_file_contents(args.file, D_CRLF)
    if len(content) < 2:
      content = get_file_contents(args.file, D_LF)
    
    if len(content) < 2:
      print(f"{C.f_yellow('Warning')}: unable to split each line by CRLF ('\\r\\n') or LF ('\\n')")
    
    if item == Item.Ip:
      output["ioc"].extend(get_items_from_list(content, Item.Ip))
    if item == Item.Url:
      output["ioc"].extend(get_items_from_list(content, Item.Url))
      output["domain"].extend(get_items_from_list(content, Item.Domain))
    if item == Item.Hash:
      output["ioc"].extend(get_items_from_list(content, Item.Hash))

  return output


def ioc_args(command: Item, args):
  '''Function begins the parsing process for each IOC and controls how each IOC is passed on the corresponding service.'''

  dbg = Dbg(args.debug)
  items = []

  if command == Item.Ip:
    dbg.dprint("IP parsing")
    items = get_arg_items(args, Item.Ip)
    
    if items != None:
      vt_ip_args(args, items["ioc"])
      otx_ip_args(args, items["ioc"])
      query_tfx_ioc(args, items["ioc"])
  
  elif command == Item.Url:
    dbg.dprint("URL parsing")
    items = get_arg_items(args, Item.Url)
    
    if items != None:
      vt_url_args(args, items)
      otx_url_args(args, items)
      query_tfx_ioc(args, items, QueryType.Url)
  
  elif command == Item.Hash:
    dbg.dprint("Hash parsing")
    items = get_arg_items(args, Item.Hash)
    
    if items != None:
      vt_hash_args(args, items["ioc"])
      otx_hash_args(args, items["ioc"])
      query_tfx_ioc(args, items["ioc"], QueryType.Hash)


def vt_hash_args(args, file_hashes: list):
  '''Function sends a list of provided hashes to the Virus Total API'''
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    responses = []
    
    if len(file_hashes) < 1:
        Dbg.eprint("No valid hashes to scan", FeatureList.Vt)
        return

    # Hashes are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_file_responses(file_hashes))

    if args.av == True:
      vt.get_av_detections(responses, Item.Hash)

    # Displays basic threat score if user enabled quick_scan.
    if check_flags(args) < 1:
      vt.file_get_quickscan(responses)
  else:
    if vt.supress_warnings == False:
      print(vt_disabled_w)


# def get_url_response_type(url: str) -> Item:
#   '''Function looks at each json response 'type' field to work out whether the information returned is for a url or a domain.'''
  
#   try:
  
#     item_t = url["type"]
#     if item_t == "url":
#       return Item.Url
#     elif item_t == "domain":
#       return Item.Domain
  
#   except KeyError:
#     return None

#   return None


# def vt_sort_urls_and_domains(responses: list, debug=False) -> [list, list]:
#   '''Function looks inside each json response to work out whether the request was for a domain or a url.
#   Once found, it will return a list of domains and urls to be parsed and displayed to the screen.'''
  
#   urls = []
#   domains = []
  
#   try:
#     for resp in responses:
#       data = resp["data"]

#       for i in data:
#         item_t = get_url_response_type(i)
#         if debug == True:
#           Dbg._dprint(f"JSON response type is {item_t}")

#         if item_t == Item.Url:
#           urls.append(resp)
#         elif item_t == Item.Domain:
#           domains.append(resp)

#   except KeyError:
#     pass
  
#   return [urls, domains]


def vt_url_args(args, urls: list):
  '''Function sends a list of provided urls/domains to the Virus Total API'''
  dbg = Dbg(args.debug)
  vt = VirusTotal(debug=args.debug, raw_json=args.raw_json)
  vt.init()

  if vt.disabled == False:
    links = []

    h_urls = []
    h_domains = []
    
    if len(urls) < 1:
      Dbg.eprint("No valid urls to scan", FeatureList.Vt)
      return

    if args.scan == True:
      url_domains = []
      url_domains.extend(urls["ioc"])
      url_domains.extend(urls["domain"])
      
      # Ips are sent to the Virus Total API and each response is stored in a list.
      example_command_1 = "ioc_scanner.py url -i http://yourUrl.com"
      example_command_2 = "ioc_scanner.py url -f pathToYourFile.txt"
      cmd = ""

      links.extend(vt.collect_url_report_links(url_domains))
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
      h_urls = []
      h_domains = []

      h_urls = vt.collect_url_responses(urls["ioc"])
      h_domains = vt.collect_url_responses(urls["domain"])

      dbg.dprint(f"regex urls: {len(urls['ioc'])}")
      dbg.dprint(f"regex domains: {len(urls['domain'])}")
      dbg.dprint(f"urls: {len(h_urls)}")
      dbg.dprint(f"domains: {len(h_domains)}")


    if args.av == True:
      vt.get_av_detections(h_urls, Item.Url)
      vt.get_av_detections(h_domains, Item.Url)

    # Displays basic threat score if user enablled quick_scan.
    if check_flags(args) < 1:
      if len(h_urls) > 0:
        vt.url_get_vtintel_quickscan(h_urls)
      if len(h_domains) > 0:
        vt.domain_get_vtintel_quickscan(h_domains)
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
      Dbg.eprint("No valid ips to scan", FeatureList.Vt)
      return

    # Ips are sent to the Virus Total API and each response is stored in a list.
    responses.extend(vt.collect_ip_responses(ips))
    
    if args.av == True:
      vt.get_av_detections(responses, Item.Ip)

    if check_flags(args) < 1:
      vt.ip_get_quickscan(responses)
  else:
    if vt.supress_warnings == False:
      print(vt_disabled_w)


def otx_url_args(args, urls: list):
  dbg = Dbg(args.debug)
  dbg.dprint("Calling otx url/domain")

  otx = AlienVault(args.debug, args.raw_json)
  otx.init()

  dbg.dprint(f"Otx has been initalized")
  dbg.dprint(f"OTX disabled: {otx.disabled}")
  dbg.dprint(f"raw_json: {otx.raw_json}")

  if otx.disabled == False:
    h_urls = []
    h_domains = []

    if len(urls) < 1:
      Dbg.eprint("No valid urls to scan", FeatureList.Otx)
      return
    
    dbg.dprint(f"Sending urls {len(urls['ioc'])} to AlienVault")
    h_urls.extend(otx.collect_responses(urls['ioc'], IndicatorType.Url))

    dbg.dprint(f"Sending domains {len(urls['domain'])} to AlienVault")
    h_domains.extend(otx.collect_responses(urls['domain'], IndicatorType.Domain))

    if check_flags(args) < 1:

      if len(h_urls) > 0:
        otx.get_quickscan(h_urls, IndicatorType.Url)
      if len(h_domains) > 0:
        otx.get_quickscan(h_domains, IndicatorType.Domain)

  else:
    if otx.supress_warnings == False:
      print(otx_disabled_w)  


def otx_hash_args(args, hashes: list):
  dbg = Dbg(args.debug)
  dbg.dprint("Calling otx hash")

  otx = AlienVault(args.debug, args.raw_json)
  otx.init()

  dbg.dprint(f"Otx has been initalized")
  dbg.dprint(f"OTX disabled: {otx.disabled}")
  dbg.dprint(f"raw_json: {otx.raw_json}")

  if otx.disabled == False:
    responses = []

    if len(hashes) < 1:
      Dbg.eprint("No valid hashes to scan", FeatureList.Otx)
      return
    
    dbg.dprint(f"Sending {len(hashes)} to AlienVault")
    responses.extend(otx.collect_responses(hashes, IndicatorType.Hash))

    if check_flags(args) < 1:
      otx.get_quickscan(responses, IndicatorType.Hash)    

  else:
    if otx.supress_warnings == False:
      print(otx_disabled_w)  


def otx_ip_args(args, ips: list):
  '''Function initalizes AlienVault, sends each IOC to the API and presents the information to the screen.'''
  
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
      Dbg.eprint("No valid ips to scan", FeatureList.Otx)
      return
    
    dbg.dprint(f"Sending {len(ips)} to AlienVault")
    responses.extend(otx.collect_responses(ips, IndicatorType.Ipv4))

    if check_flags(args) < 1:
      otx.get_quickscan(responses, IndicatorType.Ipv4)    

  else:
    if otx.supress_warnings == False:
      print(otx_disabled_w)


def query_tfx_ioc(args, iocs: list, qtype=QueryType.Ip):
  '''Function initalizes ThreatFox, sends each IOC to the API and presents the information to the screen.'''

  dbg = Dbg(args.debug)
  dbg.dprint("Querying ThreatFox for IOCs")

  tfx = ThreatFox(args.debug, args.raw_json)
  tfx.init()
  
  dbg.dprint(f"ThreatFox has been initalized")
  dbg.dprint(f"ThreatFox disabled: {tfx.disabled}")
  dbg.dprint(f"raw_json: {tfx.raw_json}")

  if tfx.disabled == False:
    ioc_list = []
    
    if qtype == QueryType.Url:
      ioc_list.extend(iocs["ioc"])
      ioc_list.extend(iocs["domain"])

    responses = []
    
    if len(iocs) < 1:
      Dbg.eprint("No valid IOCs to scan", FeatureList.Tfx)
      return
    
    if qtype == QueryType.Url:
      responses.extend(tfx.collect_ioc_responses(ioc_list, qtype))
    else:
      responses.extend(tfx.collect_ioc_responses(iocs, qtype))

    if len(responses) > 0:
      dbg.dprint(f"Sending {len(iocs)} to ThreatFox")
      tfx.get_ioc_quickscan(responses)    
  else:
    if tfx.supress_warnings == False:
      print(tfx_disabled_w)


def get_feature_status():
  '''Function reads the config file and displays whether a particular feature is enabled or disabled.'''

  pair = load_config()
  data = pair[0]
  
  table = ColorTable()
  table.align = "l"
  table.field_names = [
    C.f_yellow("Feature"),
    C.f_yellow("Enabled")
  ]

  vt = bool(check_json_error(data, "disable_vt"))
  tf = bool(check_json_error(data, "disable_tfx"))
  otx = bool(check_json_error(data, "disable_otx"))
  warnings = bool(check_json_error(data, "supress_warnings"))

  if vt == True:
    vt = C.f_red("False")
  else:
    vt = C.f_green("True")

  if tf == True:
    tf = C.f_red("False")
  else:
    tf = C.f_green("True")

  if otx == True:
    otx = C.f_red("False")
  else:
    otx = C.f_green("True")

  if warnings == True:
    warnings = C.f_red("False")
  else:
    warnings = C.f_green("True")

  table.add_rows(
    [[C.f_blue("Virus Total"), vt],
    [C.f_green("Threat Fox"), tf],
    [C.f_red("Alien Vault"), otx],
    [C.fd_yellow("Suppress Warnings"), warnings]]
  )

  print(table)