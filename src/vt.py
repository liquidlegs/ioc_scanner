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


  # Reads the config file and parses the json to retrieve the VT API key.
  def init(self):
    data = load_config()
    key = parse_config_file(data[VIRUS_TOTAL_KEY])
    self.api_key[1] = key


  def __init__(self, debug=False, vt_objects=10):
    self.debug = debug
    self.n_results = vt_objects
    self.api_key = ["x-apikey", ""]


  # Sends a GET request to the VT API about file attributes relating to a hash.
  def query_file_attributes(self, hash_id: str) -> str:
    url = f"{self.BASE_PTH_FILE_ATT}{hash_id}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  # Sends a GET request to the VT API about file behaviours relating to a hash.
  def query_file_behaviour(self, hash_id: str) -> str:
    url = f"{self.BASE_PTH_FILE_BEH}/{hash_id}/behaviours?limit={self.n_results}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  # Sends a GET request to the VT API for information about an ip address.
  def query_ip_attributes(self, ip: str) -> str:
    url = f"{self.BASE_PTH_IP_ATT}{ip}"
    response = requests.get(url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = response.text
    return text


  # Sends a POST request to the VT API which scans the url and returns a link to the report.
  def query_url_attributes(self, url: str) -> str:    
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


  # Makes a GET request to a report for the corresponding url.
  def get_url_report(self, url_response: str) -> str:
    response = requests.get(url_response, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
    })

    text = response.text
    return text


  # Returns the corresponding VT API error via the response from VT.
  def get_error_code(code: str):
    if code.lower() == "wrongcredentialserror":
      return VtApiErr.InvalidApiKey
    if code.lower() == "invalidargumenterror":
      return VtApiErr.InvalidArgument
    if code.lower() == "notfounderror":
      return VtApiErr.ResourceNotFound

    return VtApiErr.Nan


  # Kills the current process if the VT API key is invalid.
  def handle_execution_error(code: VtApiErr):
    if code == VtApiErr.InvalidApiKey:
      exit(1)


  # Displays errors returned by the VT API.
  def handle_api_error(data: str, raw_json: bool) -> VtApiErr:
    err = VtApiErr.Nan
    
    if raw_json == True:
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
    link = None

    try:
      link = content["data"]["links"]["self"]
      return link
    except KeyError:
      return link
  

  def collect_url_reports(self, urls: list, raw_json: bool):
    links = []
    
    for url in urls:
      resp = self.query_url_attributes(url)
      err = VirusTotal.handle_api_error(resp, raw_json)

      # Responses that pass error checks will be parsed.
      if err == VtApiErr.Nan:
        link = VirusTotal.url_get_report_link(json.loads(resp))
        links.append(link)


    return links


  def collect_ip_responses(self, ips: list, raw_json: bool) -> list:
    responses = []

    for ip in ips:
      resp = self.query_ip_attributes(ip)
      err = VirusTotal.handle_api_error(resp, raw_json)

      # Responses that pass error checks will be parsed.
      if err == VtApiErr.Nan:
        data = json.loads(resp)
        responses.append(data)

    return responses


  # Displays basic information and threat scores of each specified IP address to the screen.
  def ip_get_quickscan(ips: list):
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



  def hash_get_quickscan(data: str) -> str:
    pass

  
# vt = VirusTotal()
# vt.init_vt()

# data = vt.query_ip_attributes("142.251.221.78")
# text = vt.query_url_attributes("https://www.google.com")
# text = vt.query_file_behaviour("6712500bb0de148a99ec940160d3d61850e2ce3803adca8f39e9fa8621b8ea6f");