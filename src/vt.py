from src.shared import load_config, parse_config_file, VIRUS_TOTAL_KEY, VIRUS_TOTAL_DISABLED, SUPRESS_WARNINGS
from src.shared import Colour as C, Item, Dbg
import requests, enum, json, time
from prettytable.colortable import ColorTable
from datetime import datetime

class VtApiErr(enum.Enum):
  Nan = 0
  InvalidApiKey = 1
  InvalidArgument = 2
  ResourceNotFound = 3
  AuthenticationRequired = 4


class VirusTotal:

  BASE_PTH_FILE_ATT = "https://www.virustotal.com/api/v3/files/"
  BASE_PTH_FILE_BEH = "https://www.virustotal.com/api/v3/files/"
  BASE_PTH_IP_ATT = "https://www.virustotal.com/api/v3/ip_addresses/"
  BASE_PTH_URL_ATT = "https://www.virustotal.com/api/v3/urls"
  BASE_PTH_SCH = "https://www.virustotal.com/api/v3/search?query={ioc}"

  JSON_HDR = ("accept", "application/json")
  FORM_HDR = ("content-type", "application/x-www-form-urlencoded")
  CNT_LEN_HDR = "content-length"

  @classmethod
  def init(self):
    '''Reads the config file and parses the json to retrieve the VT API key.'''
    data = load_config()
    key = parse_config_file(data[VIRUS_TOTAL_KEY])
    disable_vt = parse_config_file(data[VIRUS_TOTAL_DISABLED])
    warnings = parse_config_file(data[SUPRESS_WARNINGS])

    if key != None:
      self.api_key[1] = key

    if disable_vt != None:
      self.disabled = bool(disable_vt)

    if warnings != None:
      self.supress_warnings = bool(warnings)


  @classmethod
  def is_apikey_loaded(self) -> bool:
    length = len(self.api_key[1])
    if length > 0:
      return True
    else:
      return False


  @classmethod
  def __init__(self, debug=False, vt_objects=10, raw_json=False, disabled=False):
    self.debug = debug
    self.n_results = vt_objects
    self.raw_json = raw_json
    self.disabled = disabled
    self.supress_warnings = False
    self.api_key = ["x-apikey", ""]


  def dprint(self, text: str):
    if self.debug == True:
      Dbg._dprint(text)


  @classmethod
  def query_file_attributes(self, hash_id: str) -> str:
    '''Sends a GET request to the VT API about file attributes relating to a hash.'''
    start = time.time()
    
    url = f"{self.BASE_PTH_FILE_ATT}{hash_id}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    end = time.time()
    self.dprint(self, f"Took {end - start}s to query file attributes and receive a response")

    text = response.text
    return text


  @classmethod
  def query_file_behaviour(self, hash_id: str) -> str:
    '''Sends a GET request to the VT API about file behaviours relating to a hash.'''
    url = f"{self.BASE_PTH_FILE_BEH}/{hash_id}/behaviours?limit={self.n_results}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  @classmethod
  def query_ip_attributes(self, ip: str) -> str:
    '''Sends a GET request to the VT API for information about an ip address.'''
    start = time.time()
    
    url = f"{self.BASE_PTH_IP_ATT}{ip}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    end = time.time()
    self.dprint(self, f"Took {end - start}s to query IP attributes and receive a response")

    text = response.text
    return text


  @classmethod
  def query_url_attributes(self, url: str) -> str:    
    '''Sends a POST request to the VT API which scans the url and returns a link to the report.'''
    start = time.time()

    # Prepares the api request to scan the url.
    base_url = self.BASE_PTH_URL_ATT
    payload = {"url": url}

    # Submit as form.
    response = requests.post(base_url, data=payload, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
      self.CNT_LEN_HDR: str(len(url)),
      self.FORM_HDR[0]: self.FORM_HDR[1]
    })
    
    end = time.time()
    self.dprint(self, f"Took {end - start}s to submit url and receive report link")

    # This response contains the json used to grab the report id for the scanned url.
    text = response.text
    return text


  @classmethod
  def get_url_report(self, url_response: str) -> str:
    '''# Makes a GET request to a report for the corresponding url.'''
    start = time.time()
    
    response = requests.get(url_response, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
    })

    end = time.time()
    self.dprint(self, f"Took {end - start}s to send and receive url report/response")

    text = response.text
    return text


  @staticmethod
  def get_error_code(code: str):
    '''# Returns the corresponding VT API error via the response from VT'''
    if code.lower() == "wrongcredentialserror":
      return VtApiErr.InvalidApiKey
    if code.lower() == "authenticationrequirederror":
      return VtApiErr.AuthenticationRequired
    if code.lower() == "invalidargumenterror":
      return VtApiErr.InvalidArgument
    if code.lower() == "notfounderror":
      return VtApiErr.ResourceNotFound

    return VtApiErr.Nan


  @staticmethod
  def handle_execution_error(code: VtApiErr):
    '''# Kills the current process if the VT API key is invalid.'''
    if code == VtApiErr.InvalidApiKey:
      exit(1)
    if code == VtApiErr.AuthenticationRequired:
      exit(1)


  @classmethod
  def handle_api_error(self, data: str) -> VtApiErr:
    '''# Displays errors returned by the VT API.'''
    err = VtApiErr.Nan
    
    if self.raw_json == True:
      print(data)
      exit(1)

    try:
      dt = json.loads(data)
      error = dt["error"]

      if len(error) > 0:
        msg = error["message"]
        err = VirusTotal.get_error_code(error["code"])
        print(f"{C.f_red('Error')}: ({C.f_blue('Virus Total')}) {C.fd_yellow(msg)}")

        VirusTotal.handle_execution_error(err)

      return err
    except KeyError:
      return err
    

  @staticmethod
  def url_get_report_link(content: bytes) -> str:
    '''Extracts the url link from to the url report from the VT json response.'''
    link = None

    try:
      link = content["data"]["links"]["self"]
      return link
    except KeyError:
      return link
  

  @classmethod
  def collect_url_report_links(self, urls: list):
    '''Sends each specified url to the VT API backend and retrieves the link to the url report.'''
    links = []
    
    try:
      for url in urls:
        resp = self.query_url_attributes(url)
        err = self.handle_api_error(resp)

        # Responses that pass error checks will be parsed.
        if err == VtApiErr.Nan:
          link = VirusTotal.url_get_report_link(json.loads(resp))
          links.append(link)

    except json.decoder.JSONDecodeError:
      pass

    return links


  def get_url_reputation(self, url: str) -> str:
    start = time.time()
    base_url = self.BASE_PTH_SCH.replace("{ioc}", url)
    
    response = requests.get(base_url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
    })

    end = time.time()
    self.dprint(f"Took {end - start}s to send request and receive url json response")

    text = response.text
    return text


  def collect_url_responses(self, urls: list) -> list:
    responses = []

    for url in urls:
      resp = self.get_url_reputation(url)
      err = self.handle_api_error(resp)

      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)
    
    return responses


  @classmethod
  def collect_file_responses(self, file_hashes: list) -> list:
    '''Sends a number of GET requests from a list of file hashes and collects the json responses.'''
    responses = []

    for hash in file_hashes:
      resp = self.query_file_attributes(hash)
      err = self.handle_api_error(resp)

      # Responses that pass error checks will be parsed.
      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)

    return responses


  @classmethod
  def collect_ip_responses(self, ips: list) -> list:
    '''Sends a number of GET requests from a list of IP addresses and collects the json responses'''
    responses = []

    for ip in ips:
      resp = self.query_ip_attributes(ip)
      err = self.handle_api_error(resp)

      # Responses that pass error checks will be parsed.
      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)

    return responses


  @staticmethod
  def ip_get_quickscan(ips: list):
    '''Displays basic information and threat scores of each specified IP address to the screen.'''
    print(f"Starting quickscan with {len(ips)} valid IPs")
    
    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("IP Address"), 
      C.f_yellow("M"), 
      C.f_yellow("S"), 
      C.f_yellow("H"),
      C.f_yellow("Country"),
      C.f_yellow("Continent"),
      C.f_yellow("Repuation"),
      C.f_yellow("Owner"),
      C.f_yellow("Network")
    ]

    if len(ips) < 1:
      return

    rows = 0
    for resp in ips:
      try:
        ip_addr = resp["data"]["id"]
        att = resp["data"]["attributes"]
        
        country = att["country"]
        cont = att["continent"]
        rep = int(att["reputation"])
        owner = att["as_owner"]
        network = C.f_green(att["network"])

        analysis = att["last_analysis_stats"]
        malicious = int(analysis["malicious"])
        suspicious = int(analysis["suspicious"])
        harmless = int(analysis["harmless"])

        o_mal = malicious
        o_sus = suspicious
        o_harm = harmless

        if malicious > 0:
          o_mal = C.b_red(C.f_white(malicious))
        if suspicious > 0:
          o_sus = C.fd_yellow(suspicious)
        if harmless > 0:
          o_harm = C.f_green(harmless)
        if rep < 0:
          rep = C.b_red(C.f_white(rep))

        table.add_row([C.f_green(ip_addr), o_mal, o_sus, o_harm, country, cont, rep, owner, network])
        rows += 1
      except KeyError:
        continue

    if rows > 0:
      print(table)
    else:
      print("Nothing to display")


  def check_json_error(data: str, key: str) -> str:
    try:
      out = data[key]
      return out
    except KeyError:
      return ""
    except TypeError:
      return ""


  def separate_string(input: str) -> str:
    out = ""
    
    if len(input) > 0:
      if input[len(input)-1] != ",":
        out += input + ","
    
    return out


  def url_get_vtintel_quickscan(urls: list):
    '''Displays basic information and threat scores of each specified URL to the screen.'''
    print(f"Starting scan with {len(urls)} valid urls")

    table = ColorTable()
    table.align = "l"
    table.max_width = 120
    table._max_width = {
      C.f_yellow("URL"): 100,
      C.f_yellow("M"): 3,
      C.f_yellow("S"): 3,
      C.f_yellow("H"): 3,
      C.f_yellow("ThreatNames"): 30,
      C.f_yellow("Categories"): 30,
      C.f_yellow("Rep"): 8,
      C.f_yellow("Code"): 6,
    }

    table.field_names = [
      C.f_yellow("URL"),
      C.f_yellow("M"),
      C.f_yellow("S"),
      C.f_yellow("H"),
      C.f_yellow("ThreatNames"),
      C.f_yellow("Categories"),
      C.f_yellow("Rep"),
      C.f_yellow("Code"),
    ]

    if len(urls) < 1:
      return

    rows = 0
    for resp in urls:
      try:
        data = resp["data"]

        for idx in data:
          att = idx["attributes"]
          stats = att["last_analysis_stats"]
          url = C.f_green(att["url"])
          cat = ""
          
          malicious = VirusTotal.check_json_error(stats, "malicious")
          sus = VirusTotal.check_json_error(stats, "suspicious")
          harm = VirusTotal.check_json_error(stats, "harmless")

          code = VirusTotal.check_json_error(att, "last_http_response_code")
          rep = VirusTotal.check_json_error(att, "reputation")

          categories = VirusTotal.check_json_error(att, "categories")
          force_point = VirusTotal.check_json_error(categories, "Forcepoint ThreatSeeker")
          sophos = VirusTotal.check_json_error(categories, "sophos")
          verdict_c = VirusTotal.check_json_error(categories, "Xcitium Verdict Cloud")
          root = VirusTotal.check_json_error(categories, "Webroot")

          if force_point != None:
            cat += force_point
          
          if sophos != None:
            cat = VirusTotal.separate_string(cat)
            cat += sophos
          
          if verdict_c != None:
            cat = VirusTotal.separate_string(cat)
            cat += verdict_c
          
          if root != None:
            cat = VirusTotal.separate_string(cat)
            cat += root

          if len(cat) > 0 and cat[len(cat)-1] == ",":
            cat = cat[0:len(cat)-2]

          t_names = ""
          threat_names = VirusTotal.check_json_error(att, "threat_names")

          for i in threat_names:
            t_names += i + ","

          if malicious > 0:
            malicious = C.b_red(C.f_white(malicious))
          
          if rep < 0:
            rep = C.b_red(C.f_white(rep))
          elif rep > 0:
            rep = C.f_green(rep)

          if sus > 0:
            sus = C.fd_yellow(sus)

          if harm > 0:
            harm = C.f_green(harm)

          table.add_row([url, malicious, sus, harm, t_names, cat, rep, code])
          rows += 1
        
      except KeyError:
        continue

    if rows > 0:
      print(table)
    else:
      print("Nothing to display")


  def unload_dns_records(records: str) -> str:
    out = ""

    for i in records:
      key_type = VirusTotal.check_json_error(i, "type")
      value = VirusTotal.check_json_error(i, "value")
      
      out += f"{key_type}:{value}, "

    if len(out) > 0 and out[len(out)-2] == ",":
      out = out[0:len(out)-3]
    
    return out


  def domain_get_vtintel_quickscan(domains: list):
    '''Displays basic information and threat scores of each specified Domain to the screen.'''
    print(f"Starting scan with {len(domains)} valid domains")

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("Domain"),
      C.f_yellow("M"),
      C.f_yellow("S"),
      C.f_yellow("H"),
      C.f_yellow("Category"),
      C.f_yellow("HTTPS_cert_date"),
      C.f_yellow("Created"),
      C.f_yellow("Rep"),
      C.f_yellow("DNS Records"),
      C.f_yellow("Tags")
    ]

    table._max_width = {
      C.f_yellow("Domain"): 50,
      C.f_yellow("M"): 8,
      C.f_yellow("S"): 8,
      C.f_yellow("H"): 8,
      C.f_yellow("Category"): 30,
      C.f_yellow("HTTPS_cert_date"): 10,
      C.f_yellow("Created"): 10,
      C.f_yellow("Rep"): 8,
      C.f_yellow("DNS Records"): 60,
      C.f_yellow("Tags"): 20
    }

    rows = 0
    for resp in domains:
      try:

        data = resp["data"]
        for idx in data:
          att = idx["attributes"]
          stats = VirusTotal.check_json_error(att, "last_analysis_stats")
          cat = ""
          tags = ""

          domain = VirusTotal.check_json_error(idx, "id")
          domain = C.f_green(domain)

          last_cert = VirusTotal.check_json_error(att, "last_https_certificate_date")
          create_date = VirusTotal.check_json_error(att, "creation_date")
          rep = int(VirusTotal.check_json_error(att, "reputation"))
          malicious = int(VirusTotal.check_json_error(stats, "malicious"))
          sus = int(VirusTotal.check_json_error(stats, "suspicious"))
          harm = int(VirusTotal.check_json_error(stats, "harmless"))

          categories = VirusTotal.check_json_error(att, "categories")
          force_point = VirusTotal.check_json_error(categories, "Forcepoint ThreatSeeker")
          sophos = VirusTotal.check_json_error(categories, "sophos")
          verdict_c = VirusTotal.check_json_error(categories, "Xcitium Verdict Cloud")
          root = VirusTotal.check_json_error(categories, "Webroot")
          alpha = VirusTotal.check_json_error(categories, "alphaMountain.ai")

          tag = VirusTotal.check_json_error(att, "tags")
          for i in tag:
            tags += i + " "

          if force_point != None:
            cat += force_point
          
          if sophos != None:
            cat = VirusTotal.separate_string(cat)
            cat += sophos
          
          if verdict_c != None:
            cat = VirusTotal.separate_string(cat)
            cat += verdict_c
          
          if root != None:
            cat = VirusTotal.separate_string(cat)
            cat += root
          
          if alpha != None:
            cat = VirusTotal.separate_string(cat)
            cat += alpha

          records = VirusTotal.check_json_error(att, "last_dns_records")
          dns_records = VirusTotal.unload_dns_records(records)

          if malicious > 0:
            malicious = C.b_red(C.f_white(malicious))
          if sus > 0:
            sus = C.fd_yellow(sus)
          if harm > 0:
            harm = C.f_green(harm)
          if rep < 0:
            rep = C.b_red(C.f_white(rep))

          l_cert = ""
          c_date = ""

          if last_cert != None and last_cert != "":
            l_cert = datetime.fromtimestamp(last_cert).strftime("%Y-%m-%d")
            
          if create_date != None and create_date != "":
            c_date = datetime.fromtimestamp(create_date).strftime("%Y-%m-%d")
          
          table.add_row([domain, malicious, sus, harm, cat, l_cert, c_date, rep, dns_records, tags])
          rows += 1

      except KeyError:
        continue

    if rows > 0:
      print(table)
    else:
      print("Nothing to display")


  @staticmethod
  def url_get_quickscan(urls: list):
    '''Displays basic information and threat scores of each specified URL to the screen.'''
    print(f"Starting scan with {len(urls)} valid urls")

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("URL"), 
      C.f_yellow("Malicious"), 
      C.f_yellow("Suspcious"), 
      C.f_yellow("Harmless"), 
      C.f_yellow("Undetected"), 
      C.f_yellow("Timeout")
    ]

    if len(urls) < 1:
      return

    rows = 0
    for resp in urls:
      try:
        url_info = resp["meta"]["url_info"]["url"]
        att = resp["data"]["attributes"]

        analysis = att["stats"]
        malicious = int(analysis["malicious"])
        suspicious = int(analysis["suspicious"])
        harmless = int(analysis["harmless"])
        undetected = int(analysis["undetected"])
        timeout = int(analysis["timeout"])

        o_mal = malicious
        o_sus = suspicious
        o_harm = harmless
        o_tm = timeout

        if malicious > 0:
          o_mal = C.b_red(C.f_white(malicious))
        if suspicious > 0:
          o_sus = C.fd_yellow(suspicious)
        if harmless > 0:
          o_harm = C.f_green(harmless)
        if timeout > 0:
          o_tm = C.f_blue(timeout)

        table.add_row([C.f_green(url_info), o_mal, o_sus, o_harm, undetected, o_tm])
        rows += 1
      except KeyError:
        continue

    if rows > 0:
      print(table)
    else:
      print("Nothing to display")


  def pop_string(string: str) -> str:
    out = string

    if len(string) > 0:
      out = string[0:len(string)-1]
    
    return out    


  @staticmethod
  def file_get_quickscan(hashes: str) -> str:
    '''Displays basic information and threat scores of each specified file hash to the screen.'''
    print(f"Starting scan with {len(hashes)} valid file hashes")

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("Sha256"), 
      C.f_yellow("M"), 
      C.f_yellow("S"), 
      C.f_yellow("H"), 
      C.f_yellow("Name(s)"),
      C.f_yellow("Type"),
      C.f_yellow("Threat Label"),
      C.f_yellow("Sections"),
      C.f_yellow("Imports"),
      C.f_yellow("Exports"),
      C.f_yellow("EntryPoint"),
      C.f_yellow("Rep")
    ]

    table._max_width = {
      C.f_yellow("Sha256"): 64, 
      C.f_yellow("M"): 8, 
      C.f_yellow("S"): 8, 
      C.f_yellow("H"): 8, 
      C.f_yellow("Name(s)"): 20,
      C.f_yellow("Type"): 15,
      C.f_yellow("Threat Label"): 20,
      C.f_yellow("Sections"): 8,
      C.f_yellow("Imports"): 8,
      C.f_yellow("Exports"): 8,
      C.f_yellow("EntryPoint"): 8,
      C.f_yellow("Rep"): 8
    }

    if len(hashes) < 1:
      return

    rows = 0
    for resp in hashes:
      try:
        hash = resp["data"]["id"]
        att = resp["data"]["attributes"]
        
        popular_threat = VirusTotal.check_json_error(att, "popular_threat_classification")
        threat_label = VirusTotal.check_json_error(popular_threat, "suggested_threat_label")
        type_d = VirusTotal.check_json_error(att, "type_description")
        tag = VirusTotal.check_json_error(att, "tags")
        rep = int(VirusTotal.check_json_error(att, "reputation"))

        pe_info = VirusTotal.check_json_error(att, "pe_info")
        section = VirusTotal.check_json_error(pe_info, "sections")
        import_list = VirusTotal.check_json_error(pe_info, "import_list")
        export_list = VirusTotal.check_json_error(pe_info, "exports")
        entry = {VirusTotal.check_json_error(pe_info, 'entry_point')}

        if entry != None and entry != "":
          entry = f"0x{entry}"

        names = ""
        imports = 0
        exports = len(export_list)
        sections = len(section)

        analysis = att["last_analysis_stats"]
        malicious = int(analysis["malicious"])
        suspicious = int(analysis["suspicious"])
        harmless = int(analysis["harmless"])
        exe_names = VirusTotal.check_json_error(att, "names")

        for i in exe_names:
          names += i + ","

        names = VirusTotal.pop_string(names)

        for i in import_list:
          functions = VirusTotal.check_json_error(i, "imported_functions")
          imports += len(functions)

        o_mal = malicious
        o_sus = suspicious
        o_harm = harmless

        if malicious > 0:
          o_mal = C.b_red(C.f_white(malicious))
        if suspicious > 0:
          o_sus = C.fd_yellow(suspicious)
        if harmless > 0:
          o_harm = C.f_green(harmless)

        if rep > 0:
          rep = C.f_green(rep)
        elif rep < 0:
          rep = C.b_red(C.f_white(rep))

        hash = C.f_green(hash)
        entry = C.fd_yellow(entry)

        table.add_row([hash, o_mal, o_sus, o_harm, names, type_d, threat_label, sections, imports, exports, entry, rep])
        rows += 1
      except KeyError:
        continue

    if rows > 0:
      print(table)
    else:
      print("Nothing to display")

  
  @staticmethod
  def get_av_detections(data: list, item: Item):
    print(f"Sending {len(data)} items to the VT API backend")
    
    table_store = []

    if item == Item.Hash:
      engine_keys = [
        "Bkav" ,"Lionic" ,"tehtris" ,"DrWeb" ,"MicroWorld-eScan" "FireEye" ,"CAT-QuickHeal" ,"ALYac" ,"Malwarebytes" ,"Zillya" ,"Sangfor" ,"K7AntiVirus"
        ,"BitDefender" ,"K7GW" ,"CrowdStrike" ,"BitDefenderTheta" ,"VirIT" ,"Cyren" ,"SymantecMobileInsight" ,"Symantec" ,"Elastic" ,"ESET-NOD32" ,"APEX" 
        ,"Paloalto" ,"ClamAV" ,"Kaspersky" ,"Alibaba" ,"NANO-Antivirus" ,"ViRobot" ,"Rising" ,"Ad-Aware" ,"Trustlook" ,"TACHYON" ,"Sophos" ,"Comodo"
        ,"F-Secure" ,"Baidu" ,"VIPRE" ,"TrendMicro" ,"McAfee-GW-Edition" ,"Trapmine" ,"Emsisoft" ,"Ikarus" ,"Avast-Mobile" ,"Jiangmin" ,"Webroot" ,"Google" 
        ,"Avira" ,"Antiy-AVL" ,"Kingsoft" ,"Microsoft" ,"Gridinsoft" ,"Arcabit" ,"SUPERAntiSpyware" ,"ZoneAlarm" ,"GData" ,"Cynet" ,"BitDefenderFalx" ,"AhnLab-V3" 
        ,"Acronis" ,"McAfee" ,"MAX" ,"VBA32" ,"Cylance" ,"Panda" ,"Zoner" ,"TrendMicro-HouseCall" ,"Tencent" ,"Yandex" ,"SentinelOne" ,"MaxSecure" ,"Fortinet" ,"AVG" 
        ,"Cybereason" ,"Avast"
      ]

      for resp in data:
        table = ColorTable()
        table.align = "l"
        table.field_names = [
          C.f_yellow("Engine Name"),
          C.f_yellow("Category"),
          C.f_yellow("Result"),
          C.f_yellow("Engine Version"),
          C.f_yellow("Engine Update"),
          C.f_yellow("Method")
        ]

        att = resp["data"]["attributes"]

        analysis = att["last_analysis_results"]
        for index in engine_keys:

          try:
            av = analysis[index]
            engine_name = C.f_yellow(av["engine_name"])
            cat = av["category"]
            res = av["result"]
            engine_ver = C.fd_cyan(av["engine_version"])
            engine_up = C.fd_yellow(av["engine_update"])
            meth = C.f_magenta(av["method"])

            if cat.lower() == "malicious":
              cat = C.bd_red(C.f_white(cat))
            elif cat.lower() == "undetected":
              cat = C.f_green(cat)
            elif cat.lower() == "type-unsupported":
              cat = C.f_blue(cat)
            elif cat.lower() == "timeout":
              cat = C.f_blue(cat)

            if res != None:
              res = C.f_red(res)

            table.add_row([engine_name, cat, res, engine_ver, engine_up, meth])
          except KeyError:
            pass

        table_store.append(table)


      for table in table_store:
        print(table.get_string(sortby=C.f_yellow("Category")))
    

    elif item == Item.Ip:
      engine_keys = [
        "Bkav" ,"CMC Threat Intelligence" ,"Snort IP sample list" ,"0xSI_f33d" ,"ViriBack" ,"PhishLabs" "K7AntiVirus" ,"CINS Army" ,"Quttera" ,"PrecisionSec" 
        ,"OpenPhish" ,"VX Vault" ,"ArcSight Threat Intelligence" ,"Scantitan" ,"AlienVault" ,"Sophos" ,"Phishtank" ,"Cyan" ,"Spam404" ,"SecureBrain" ,"CRDF" 
        ,"Fortinet" ,"alphaMountain.ai" ,"Lionic" ,"Cyble" ,"Seclookup" ,"Xcitium Verdict Cloud" ,"Google Safebrowsing" ,"SafeToOpen" ,"ADMINUSLabs" ,"ESTsecurity" 
        ,"Juniper Networks" ,"Heimdal Security" ,"AutoShun" ,"Trustwave" ,"AICC (MONITORAPP)" ,"CyRadar" ,"Dr.Web" ,"Emsisoft" ,"Abusix" ,"Webroot" ,"Avira" 
        ,"securolytics" ,"Antiy-AVL" ,"AlphaSOC" ,"Acronis" ,"Quick Heal" ,"URLQuery" ,"Viettel Threat Intelligence" ,"DNS8" ,"benkow.cc" ,"EmergingThreats" 
        ,"Chong Lua Dao" ,"Yandex Safebrowsing" ,"Lumu" ,"zvelo" ,"Kaspersky" ,"Segasec" ,"Sucuri SiteCheck" ,"desenmascara.me" ,"CrowdSec" ,"Cluster25" ,"SOCRadar" 
        ,"URLhaus" ,"PREBYTES" ,"StopForumSpam" ,"Blueliv" ,"Netcraft" ,"ZeroCERT" ,"Phishing Database" ,"MalwarePatrol" ,"IPsum" ,"Malwared" ,"BitDefender" 
        ,"GreenSnow" ,"G-Data" ,"VIPRE" ,"SCUMWARE.org" ,"PhishFort" ,"malwares.com URL checker" ,"Forcepoint ThreatSeeker" ,"Criminal IP" ,"Certego" ,"ESET" 
        ,"Threatsourcing" ,"ThreatHive" ,"Bfore.Ai PreCrime"
      ]

      for resp in data:
        table = ColorTable()
        table.align = "l"
        table.field_names = [
          C.f_yellow("Engine Name"),
          C.f_yellow("Category"),
          C.f_yellow("Result"),
          C.f_yellow("Method")
        ]

        att = resp["data"]["attributes"]

        analysis = att["last_analysis_results"]
        for index in engine_keys:

          try:
            av = analysis[index]
            engine_name = C.f_yellow(av["engine_name"])
            cat = av["category"]
            res = av["result"]
            meth = C.f_magenta(av["method"])

            if cat.lower() == "malicious":
              cat = C.bd_red(C.f_white(cat))
            elif cat.lower() == "undetected":
              cat = C.f_green(cat)
            elif cat.lower() == "harmless":
              cat = C.f_green(cat)
            elif cat.lower() == "type-unsupported":
              cat = C.f_blue(cat)
            elif cat.lower() == "timeout":
              cat = C.f_blue(cat)

            if res.lower() == "clean":
              res = C.f_green(res) 
            elif res.lower() == "malware":
              res = C.f_red(res)
            elif res.lower() == "malicious":
              res = C.f_red(res)
            elif res.lower() == "phishing":
              res = C.fd_yellow(res)

            table.add_row([engine_name, cat, res, meth])
          except KeyError:
            pass

        table_store.append(table)


      for table in table_store:
        print(table.get_string(sortby=C.f_yellow("Category")))

    
    elif item == Item.Url:
      engine_keys = [
        "Bkav" ,"CMC Threat Intelligence" ,"Snort IP sample list" ,"0xSI_f33d" ,"ViriBack" ,"PhishLabs" ,"K7AntiVirus" ,"CINS Army" ,"Quttera" ,"BlockList" 
        ,"PrecisionSec" ,"OpenPhish" ,"VX Vault" ,"Feodo Tracker" ,"ADMINUSLabs" ,"Scantitan" ,"AlienVault" ,"Sophos" ,"Phishtank" ,"Cyan" ,"Spam404" ,"SecureBrain" 
        ,"AutoShun" ,"Rising" ,"Fortinet" ,"alphaMountain.ai" ,"Lionic" ,"Cyble" ,"Seclookup" ,"Xcitium Verdict Cloud" ,"Artists Against 419" ,"Google Safebrowsing" 
        ,"SafeToOpen" ,"ArcSight Threat Intelligence" ,"ESTsecurity" ,"Juniper Networks" ,"Heimdal Security" ,"CRDF" ,"Trustwave" ,"AICC (MONITORAPP)" ,"CyRadar" 
        ,"Dr.Web" ,"Emsisoft" ,"Abusix" ,"Webroot" ,"Avira" ,"securolytics" ,"Antiy-AVL" ,"AlphaSOC" ,"Acronis" ,"Quick Heal" ,"URLQuery" ,"Viettel Threat Intelligence" 
        ,"DNS8" ,"benkow.cc" ,"EmergingThreats" ,"Chong Lua Dao" ,"Yandex Safebrowsing" ,"Lumu" ,"Kaspersky" ,"Sucuri SiteCheck" ,"desenmascara.me" 
        ,"CrowdSec" ,"Cluster25" ,"SOCRadar" ,"URLhaus" ,"PREBYTES" ,"StopForumSpam" ,"Blueliv" ,"Netcraft" ,"ZeroCERT" ,"Phishing Database" ,"MalwarePatrol" 
        ,"Sangfor" ,"IPsum" ,"Malwared" ,"BitDefender" ,"GreenSnow" ,"G-Data" ,"VIPRE" ,"SCUMWARE.org" ,"PhishFort" ,"malwares.com URL checker" 
        ,"Forcepoint ThreatSeeker" ,"Criminal IP" ,"Certego" ,"ESET" ,"Threatsourcing" ,"ThreatHive" ,"Bfore.Ai PreCrime"
      ]

      for resp in data:
        test_table = ColorTable()
        test_table.align = "l"
        test_table.field_names = [
          C.f_yellow("Engine Name"),
          C.f_yellow("Category"),
          C.f_yellow("Result"),
          C.f_yellow("Method")
        ]

        att = resp["data"]["attributes"]

        analysis = att["results"]
        for index in engine_keys:

          try:
            av = analysis[index]
            engine_name = C.f_yellow(av["engine_name"])
            cat = av["category"]
            res = av["result"]
            meth = C.f_magenta(av["method"])

            if cat.lower() == "malicious":
              cat = C.bd_red(C.f_white(cat))
            elif cat.lower() == "undetected":
              cat = C.f_green(cat)
            elif cat.lower() == "harmless":
              cat = C.f_green(cat)
            elif cat.lower() == "type-unsupported":
              cat = C.f_blue(cat)
            elif cat.lower() == "timeout":
              cat = C.f_blue(cat)

            if res.lower() == "clean":
              res = C.f_green(res) 
            elif res.lower() == "malware":
              res = C.f_red(res)
            elif res.lower() == "malicious":
              res = C.f_red(res)

            test_table.add_row([engine_name, cat, res, meth])
          except KeyError:
            pass

        table_store.append(test_table)


      for table in table_store:
        print(table.get_string(sortby=C.f_yellow("Category")))
