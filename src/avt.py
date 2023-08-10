from src.shared import load_config, parse_config_file, ALIEN_VAULT_KEY
from src.shared import Colour as C, Item
import requests
import enum, json
from prettytable.colortable import ColorTable

class Indicator(enum.Enum):
  general = 0
  reputation = 1
  geo = 2
  malware = 3
  url_list = 4
  passive_dns = 5
  whois = 6
  analysis = 7


class AlienVault:

  IND_IPv4 = "/api/v1/indicators/IPv4/{ip}/{section}"
  IND_IPv6 = "/api/v1/indicators/IPv6/{ip}/{section}"
  IND_DOMAIN = "/api/v1/indicators/domain/{domain}/{section}"
  IND_HOSTNAME = "/api/v1/indicators/hostname/{hostname}/{section}"
  IND_FILEHASH = "/api/v1/indicators/file/{file_hash}/{section}"
  IND_URL = "/api/v1/indicators/url/{url}/{section}"
  IND_NIDS = "/api/v1/indicators/nids/{nids}/{section}"
  IND_CORRELATION = "/api/v1/indicators/correlation-rule/{correlationrule}/{section}"

  JSON_HDR = ("accept", "application/json")
  FORM_HDR = ("content-type", "application/x-www-form-urlencoded")

  
  @classmethod
  def init(self):
    '''Reads the config file and parses the json to retrieve the OTX API key.'''
    data = load_config()
    key = parse_config_file(data[ALIEN_VAULT_KEY])
    self.api_key[1] = key


  @classmethod
  def __init__(self, debug=False, raw_json=False):
    self.debug = debug
    self.raw_json = raw_json
    self.api_key = ["x-apikey", ""]


  def get_ip_indicators():
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