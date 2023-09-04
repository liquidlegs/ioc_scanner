from src.shared import load_config, parse_config_file, ALIEN_VAULT_KEY
from src.shared import Colour as C, Item
import requests
import enum, json
from prettytable.colortable import ColorTable

# useful documentation for OTX headers
# https://gist.github.com/chrisdoman/3cccfbf6f07cf007271bec583305eb92

class Indicator(enum.Enum):
  general = 0
  reputation = 1
  geo = 2
  malware = 3
  url_list = 4
  passive_dns = 5
  http_scans = 6
  nids_list = 7
  whois = 8
  analysis = 9


class OtxApiErr(enum.Enum):
  Nan = 0
  NotFound = 1
  DataButEmpty = 2
  Null = 3
  SubRequired = 4


class Ip(enum.Enum):
  V4 = 0
  V6 = 1


class AlienVault:

  IND_IPv4 = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/{section}"
  IND_IPv6 = "https://otx.alienvault.com/api/v1/indicators/IPv6/{ip}/{section}"
  IND_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{section}"
  IND_HOSTNAME = "https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/{section}"
  IND_FILEHASH = "https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/{section}"
  IND_URL = "https://otx.alienvault.com/api/v1/indicators/url/{url}/{section}"
  IND_NIDS = "https://otx.alienvault.com/api/v1/indicators/nids/{nids}/{section}"
  IND_CORRELATION = "https://otx.alienvault.com/api/v1/indicators/correlation-rule/{correlationrule}/{section}"

  JSON_HDR = ("accept", "application/json")
  FORM_HDR = ("content-type", "application/x-www-form-urlencoded")

  
  @classmethod
  def init(self):
    '''Reads the config file and parses the json to retrieve the OTX API key.'''
    data = load_config()
    key = parse_config_file(data[ALIEN_VAULT_KEY])
    
    if key != None:
      self.api_key[1] = key


  @classmethod
  def is_apikey_loaded(self) -> bool:
    length = len(self.api_key[1])
    if length > 0:
      return True
    else:
      return False


  @classmethod
  def __init__(self, debug=False, raw_json=False):
    self.debug = debug
    self.raw_json = raw_json
    self.api_key = ["X-OTX-API-KEY", ""]


  def get_ip_quickscan():
    pass


  def handle_otx_error(self, data: str, indicator: Indicator) -> OtxApiErr:
    err = OtxApiErr.Nan
    
    if self.raw_json == True:
      print(data)
      exit(1)

    try:
      temp_err = OtxApiErr.Nan
      dt = json.loads(data)

      if indicator == Indicator.analysis:
        msg = re_contains(r"(not\s+found|notfound)", dt["detail"])

        if msg == "not found" or msg == "notfound":
          err = OtxApiErr.NotFound
          print(f"{C.f_red('Error')}: ({C.f_magenta('AlienVault')}) {C.fd_yellow(msg)}")

      return err
    except KeyError:
      return err

    pass


  def get_ip_indicators(self, ip_type: Ip, data: str, ind: Indicator):
    base_url = ""
    
    if ip_type == Ip.V4:
      base_url = self.IND_IPv4.replace("{ip}", data)
    elif ip_type == Ip.V6:
      base_url = self.IND_IPv4.replace("{ip}", data)

    if ind == Indicator.general:
      base_url = base_url.replace("{section}", "general")
    elif ind == Indicator.reputation:
      base_url = base_url.replace("{section}", "reputation")
    elif ind == Indicator.geo:
      base_url = base_url.replace("{section}", "geo")
    elif ind == Indicator.malware:
      base_url = base_url.replace("{section}", "malware")
    elif ind == Indicator.url_list:
      base_url = base_url.replace("{section}", "url_list")
    elif ind == Indicator.passive_dns:
      base_url = base_url.replace("{section}", "passive_dns")
    elif ind == Indicator.http_scans:
      base_url = base_url.replace("{section}", "http_scans")
    elif ind == Indicator.nids_list:
      base_url = base_url.replace("{section}", "nids_list")

    # print(f"url: {base_url}")
    req = requests.get(base_url, headers={
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    })

    text = req.text
    return text


  def collect_ip_responses(self, ips: list) -> list:
    out = []

    for address in ips:
      pulses = self.get_ip_indicators(Ip.V4, address, Indicator.general)
      http_scans = self.get_ip_indicators(Ip.V4, address, Indicator.http_scans)
      passive_dns = self.get_ip_indicators(Ip.V4, address, Indicator.passive_dns)
      malware_s = self.get_ip_indicators(Ip.V4, address, Indicator.malware)      

      out.append([pulses, http_scans, passive_dns, malware_s])
    
    return out


  def get_ip_quickscan(ips: list):    
    
    
    pass


  def get_domain_indictors():
    pass


  def get_hostname_indictators():
    pass


  def get_filehash_indicators():
    pass


  def get_url_indicators():
    pass


  def get_nid_indicators():
    pass


  def get_correlation_indicators():
    pass