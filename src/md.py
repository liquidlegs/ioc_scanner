from src.shared import load_config, parse_config_file, METADF_KEY, METADF_DISABLED
from src.shared import Dbg, Colour as C
import requests, time


class NbrItems:
  SINGLE = 0
  BULK = 1


class ItemType:
  IP = 0
  HASH = 1
  URL = 3
  DOMAIN = 4


class MetaDenderCloud:
  
  BASE_IP_PTH_SINGLE = "https://api.metadefender.com/v4/ip/{ip}"
  BASE_IP_PTH_BULK = "https://api.metadefender.com/v4/ip/"
  BASE_URL_PTH_SINGLE = "https://api.metadefender.com/v4/url/{url}"
  BASE_URL_PTH_BULK = "https://api.metadefender.com/v4/url/"
  BASE_DOM_PTH_SINGLE = "https://api.metadefender.com/v4/domain/{domain}"
  BASE_DOM_PTH_BULK = "https://api.metadefender.com/v4/domain/"

  JSON_HDR = ["accept", "application/json"]

  def init(self):
    '''Reads the config file and parses the json to retrieve the VT API key.'''
    data = load_config()
    key = parse_config_file(data[METADF_KEY])
    disable_md = parse_config_file(data[METADF_DISABLED])

    if key != None:
      self.api_key[1] = key

    if disable_md != None:
      self.disabled = disable_md


  def is_apikey_loaded(self) -> bool:
    length = len(self.api_key[1])
    if length > 0:
      return True
    else:
      return False


  def __init__(self, debug=False, raw_json=False, disabled=False):
    self.debug = debug
    self.raw_json = raw_json
    self.disabled = disabled
    self.api_key = ["apikey", ""]

  
  def dprint(self, text: str):
    if self.debug == True:
      Dbg._dprint(text)


  def get_ip_rep(self, ips: list, nbr: NbrItems) -> str:
    start = time.time()
    base = ""
    text = ""
    resp = None

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }

    if nbr == NbrItems.SINGLE:
      base = self.BASE_URL_PTH_SINGLE.replace("{ip}", ips[0])
      resp = requests.post(base, headers=header, data={"address": ips})

    else:
      base = self.BASE_IP_PTH_BULK

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    # text = resp.text
    # return text
    pass


  def get_hash_rep(self, hashes: list, nbr: NbrItems):
    pass


  def get_url_rep(self, urls: list, nbr: NbrItems, i_type: ItemType):
    pass