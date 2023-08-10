from src.shared import load_config, parse_config_file, VIRUS_TOTAL_KEY
from src.shared import Colour as C
import requests
import enum, json
from prettytable.colortable import ColorTable

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

  
# vt = VirusTotal()
# vt.init_vt()

# data = vt.query_ip_attributes("142.251.221.78")
# text = vt.query_url_attributes("https://www.google.com")
# text = vt.query_file_behaviour("6712500bb0de148a99ec940160d3d61850e2ce3803adca8f39e9fa8621b8ea6f");