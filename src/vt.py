from src.shared import load_config, parse_config_file, VIRUS_TOTAL_KEY
from src.shared import Colour as C, Item
import requests
import enum, json
from prettytable.colortable import ColorTable, Theme

class VtApiErr(enum.Enum):
  Nan = 0
  InvalidApiKey = 1
  InvalidArgument = 2
  ResourceNotFound = 3

class VirusTotal:

  BASE_PTH_FILE_ATT = "https://www.virustotal.com/api/v3/files/"
  BASE_PTH_FILE_BEH = "https://www.virustotal.com/api/v3/files/"
  BASE_PTH_IP_ATT = "https://www.virustotal.com/api/v3/ip_addresses/"
  BASE_PTH_URL_ATT = "https://www.virustotal.com/api/v3/urls"

  JSON_HDR = ("accept", "application/json")
  FORM_HDR = ("content-type", "application/x-www-form-urlencoded")


  def init(self):
    '''Reads the config file and parses the json to retrieve the VT API key.'''
    data = load_config()
    key = parse_config_file(data[VIRUS_TOTAL_KEY])
    self.api_key[1] = key


  def __init__(self, debug=False, vt_objects=10, raw_json=False):
    self.debug = debug
    self.n_results = vt_objects
    self.raw_json = raw_json
    self.api_key = ["x-apikey", ""]


  def query_file_attributes(self, hash_id: str) -> str:
    '''Sends a GET request to the VT API about file attributes relating to a hash.'''
    url = f"{self.BASE_PTH_FILE_ATT}{hash_id}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  def query_file_behaviour(self, hash_id: str) -> str:
    '''Sends a GET request to the VT API about file behaviours relating to a hash.'''
    url = f"{self.BASE_PTH_FILE_BEH}/{hash_id}/behaviours?limit={self.n_results}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  def query_ip_attributes(self, ip: str) -> str:
    '''Sends a GET request to the VT API for information about an ip address.'''
    url = f"{self.BASE_PTH_IP_ATT}{ip}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  def query_url_attributes(self, url: str) -> str:    
    '''Sends a POST request to the VT API which scans the url and returns a link to the report.'''
    # Prepares the api request to scan the url.
    base_url = self.BASE_PTH_URL_ATT
    payload = {"url": url}

    # Submit as form.
    response = requests.post(base_url, data=payload, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
      self.FORM_HDR[0]: self.FORM_HDR[1]
    })
    
    # This response contains the json used to grab the report id for the scanned url.
    text = response.text
    return text


  def get_url_report(self, url_response: str) -> str:
    '''# Makes a GET request to a report for the corresponding url.'''
    response = requests.get(url_response, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
    })

    text = response.text
    return text


  def get_error_code(code: str):
    '''# Returns the corresponding VT API error via the response from VT'''
    if code.lower() == "wrongcredentialserror":
      return VtApiErr.InvalidApiKey
    if code.lower() == "invalidargumenterror":
      return VtApiErr.InvalidArgument
    if code.lower() == "notfounderror":
      return VtApiErr.ResourceNotFound

    return VtApiErr.Nan


  def handle_execution_error(code: VtApiErr):
    '''# Kills the current process if the VT API key is invalid.'''
    if code == VtApiErr.InvalidApiKey:
      exit(1)


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
    

  def url_get_report_link(content: bytes) -> str:
    '''Extracts the url link from to the url report from the VT json response.'''
    link = None

    try:
      link = content["data"]["links"]["self"]
      return link
    except KeyError:
      return link
  

  def collect_url_reports(self, urls: list):
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


  def ip_get_quickscan(ips: list):
    '''Displays basic information and threat scores of each specified IP address to the screen.'''
    print(f"Starting quickscan with {len(ips)} valid IPs")
    
    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("IP Address"), 
      C.f_yellow("Malicious"), 
      C.f_yellow("Suspcious"), 
      C.f_yellow("Harmless"), 
      C.f_yellow("Undetected"), 
      C.f_yellow("Timeout")
    ]

    if len(ips) < 1:
      return

    for resp in ips:
      ip_addr = resp["data"]["id"]
      att = resp["data"]["attributes"]

      analysis = att["last_analysis_stats"]
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

      table.add_row([C.f_green(ip_addr), o_mal, o_sus, o_harm, undetected, o_tm])

    print(table)


  def url_get_quickscan(urls: list):
    '''Displays basic information and threat scores of each specified URL to the screen.'''
    print(f"Starting quickscan with {len(urls)} valid urls")

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
      except KeyError:
        pass

    print(table)



  def file_get_quickscan(hashes: str) -> str:
    '''Displays basic information and threat scores of each specified file hash to the screen.'''
    print(f"Starting quickscan with {len(hashes)} valid file hashes")

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("File Hash"), 
      C.f_yellow("Malicious"), 
      C.f_yellow("Suspcious"), 
      C.f_yellow("Harmless"), 
      C.f_yellow("Undetected"), 
      C.f_yellow("Timeout")
    ]

    if len(hashes) < 1:
      return

    for resp in hashes:
      hash = resp["data"]["id"]
      att = resp["data"]["attributes"]

      analysis = att["last_analysis_stats"]
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

      table.add_row([C.f_green(hash), o_mal, o_sus, o_harm, undetected, o_tm])

    print(table)

  
  def get_av_detections(data: str, item: Item):
    table = ColorTable()
    table.align = "l"

    if item == Item.Hash:
      table.field_names = [
        C.f_yellow("Engine Name"),
        C.f_yellow("Category"),
        C.f_yellow("Result"),
        C.f_yellow("Engine Version"),
        C.f_yellow("Engine Update"),
        C.f_yellow("Method")
      ]

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

      print(table.get_string(sortby=C.f_yellow("Category")))
    

    elif item == Item.Ip:
      table.field_names = [
        C.f_yellow("Engine Name"),
        C.f_yellow("Category"),
        C.f_yellow("Result"),
        C.f_yellow("Method")
      ]

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

      print(table.get_string(sortby=C.f_yellow("Category")))

    
    elif item == Item.Url:
      # analysis = data["data"]["attributes"]["results"]
      table.field_names = [
        C.f_yellow("Engine Name"),
        C.f_yellow("Category"),
        C.f_yellow("Result"),
        C.f_yellow("Method")
      ]

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

            table.add_row([engine_name, cat, res, meth])
          except KeyError:
            pass

      print(table.get_string(sortby=C.f_yellow("Category")))