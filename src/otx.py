from src.shared import load_config, parse_config_file, ALIEN_VAULT_KEY, ALIEN_VAULT_DISABLED, SUPRESS_WARNINGS
from src.shared import Colour as C, Item, Dbg, check_json_error
import requests
import enum, json, re
from prettytable.colortable import ColorTable
from json.decoder import JSONDecodeError
from requests.exceptions import ReadTimeout

# useful documentation for OTX headers
# https://gist.github.com/chrisdoman/

ALIEN_VAULT_MAX_TAGS = 40
ALIEN_VAULT_MAX_FAM = 5

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


class IndicatorType(enum.Enum):
  Ipv4 = 0
  Ipv6 = 1
  Url = 2
  Domain = 3
  Hash = 4


class OtxApiErr(enum.Enum):
  Nan = 0
  NotFound = 1
  DataButEmpty = 2
  Null = 3
  SubRequired = 4


class Ip(enum.Enum):
  V4 = 0
  V6 = 1


class AlienVault(Dbg):

  IND_IPv4 = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/{section}"
  IND_IPv6 = "https://otx.alienvault.com/api/v1/indicators/IPv6/{ip}/{section}"
  IND_DOMAIN = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{section}"
  IND_HOSTNAME = "https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/{section}"
  IND_FILEHASH = "https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/{section}"
  IND_URL = "https://otx.alienvault.com/api/v1/indicators/url/{url}/{section}"
  IND_SURL = "https://otx.alienvault.com/api/v1/indicators/submit_url"
  IND_NIDS = "https://otx.alienvault.com/api/v1/indicators/nids/{nids}/{section}"
  IND_CORRELATION = "https://otx.alienvault.com/api/v1/indicators/correlation-rule/{correlationrule}/{section}"

  JSON_HDR = ("accept", "application/json")
  FORM_HDR = ("content-type", "application/x-www-form-urlencoded")

  
  def init(self):
    '''Reads the config file and parses the json to retrieve the OTX API key.'''
    data_pair = load_config()
    data = data_pair[0]
    key = parse_config_file(data[ALIEN_VAULT_KEY])
    disable_otx = parse_config_file(data[ALIEN_VAULT_DISABLED])
    warnings = parse_config_file(data[SUPRESS_WARNINGS])

    if key != None:
      self.api_key[1] = key

    if disable_otx != None:
      self.disabled = bool(disable_otx)

    if warnings != None:
      self.supress_warnings = bool(warnings)


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
    self.supress_warnings = False
    self.api_key = ["X-OTX-API-KEY", ""]


  def handle_otx_error(self, data: str) -> OtxApiErr:
    err = OtxApiErr.Nan
    
    if self.raw_json == True:
      print(data)
      exit(1)

    try:
      dt = json.loads(data)
      ind = dt["indicator"]

      return err
    except TypeError:
      return OtxApiErr.NotFound
    except KeyError:
      return OtxApiErr.NotFound
    except JSONDecodeError:
      return OtxApiErr.Null


  def get_ip_indicators(self, ip_type: Ip, data: str, ind: Indicator):
    base_url = ""
    
    if ip_type == Ip.V4:
      base_url = self.IND_IPv4.replace("{ip}", data)
    elif ip_type == Ip.V6:
      base_url = self.IND_IPv6.replace("{ip}", data)

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

    try:
      req = requests.get(base_url, timeout=3, headers={
        self.JSON_HDR[0]: self.JSON_HDR[1],
        self.api_key[0]: self.api_key[1]
      })
    except ReadTimeout:
      return "None"

    text = req.text
    return text


  def get_indicator(self, id_type: IndicatorType, data: str):
    base_url = ""

    if id_type == IndicatorType.Ipv4:
      base_url = self.IND_IPv4.replace("{ip}", data)
    elif id_type == IndicatorType.Ipv6:
      base_url = self.IND_IPv6.replace("{ip}", data)
    elif id_type == IndicatorType.Url:
      base_url = self.IND_URL.replace("{url}", data)
    elif id_type == IndicatorType.Domain:
      base_url = self.IND_DOMAIN.replace("{domain}", data)
    elif id_type == IndicatorType.Hash:
      base_url = self.IND_FILEHASH.replace("{file_hash}", data)

    if base_url != "":
      base_url = base_url.replace("{section}", "general")

    try:
      req = requests.get(base_url, timeout=3, headers={
        self.JSON_HDR[0]: self.JSON_HDR[1],
        self.api_key[0]: self.api_key[1]
      })
    except ReadTimeout:
      return "None"

    text = req.text
    return text


  def collect_responses(self, inds: list, id_type: IndicatorType) -> list:
    out = []

    for address in inds:
      general = self.get_indicator(id_type, address)

      self.dprint(f"Checking {address}")
      err = self.handle_otx_error(general)

      if err == OtxApiErr.Nan:
        data = json.loads(general)
        out.append(data)

    return out


  def get_highlighted_text(text: str) -> str:
    try:
      out = re.search(
        r"(malware|ransom|botnet|wannacry|malicious|webscanner|scanner|trojan|apt|worm|spam|phishing|exe|dll|emotet|mirai|dridex|redlinestealer|agenttesla|smoke|amadey|formbook|stealc|lummastealer)",
      text, re.IGNORECASE).group(0)

      return C.bd_red(C.f_white(out))
    except AttributeError:
      return text


  def get_pulse_tags(info: str):
    pulses = check_json_error(info, "pulses")
    tags = []

    if pulses != None and pulses != "":
      for i in pulses:
        temp_tags = check_json_error(i, "tags")

        if len(temp_tags) > 0:
          tags.extend(temp_tags)

    dedup_tags = list(set(tags))
    return dedup_tags


  def get_pulse_information(pulses: str) -> str:
    output = {
      "families": "",
      "tags": ""
    }

    temp_fam = []
    temp_tags = []
    s_fam = ""
    s_tags = ""

    for i in pulses:
      families = check_json_error(i, "malware_families")
      tags = check_json_error(i, "tags")

      if families != None and families != "":
        temp_fam.append(families)

      if tags != None and tags != "":
        temp_tags.append(tags)


    fam_counter = 0
    for i in temp_fam:

      for idx in range(len(i)):
        if fam_counter > ALIEN_VAULT_MAX_FAM:
          break

        name = check_json_error(i[idx], "display_name")
        
        if idx == len(i)-1:
          s_fam += name
        else:
          s_fam += name + ","

        fam_counter += 1
    

    tag_counter = 0
    for i in temp_tags:

      for idx in range(len(i)):
        
        if tag_counter > ALIEN_VAULT_MAX_TAGS:
          break

        if idx == len(i)-1:
          s_tags += AlienVault.get_highlighted_text(i[idx])
        else:
          s_tags += AlienVault.get_highlighted_text(i[idx]) + ","

        tag_counter += 1

    
    if s_fam != "":
      output["families"] = s_fam

    if s_tags != "":
      output["tags"] = s_tags

    return output


  def get_quickscan(self, iocs: list, ind: IndicatorType):
    table = ColorTable()
    table.align = "l"
    rows = 0

    if ind == IndicatorType.Ipv4 or ind == IndicatorType.Ipv6:
      self.dprint(f"Scanning {len(iocs)} valid ips")

      table.field_names = [
        C.f_yellow("IP"),
        C.f_yellow("Validation"),
        C.f_yellow("ASN"),
        C.f_yellow("Code"),
        C.f_yellow("Pulses"),
        C.f_yellow("Rep"),
        C.f_yellow("Tags")
      ]

      table._max_width = {
        C.f_yellow("IP"): 40,
        C.f_yellow("Validation"): 25,
        C.f_yellow("ASN"): 30,
        C.f_yellow("Code"): 8,
        C.f_yellow("Pulses"): 8,
        C.f_yellow("Rep"): 8,
        C.f_yellow("Tags"): 100
      }

      for i in iocs:
        rep = check_json_error(i, "reputation")
        ip = C.f_green(check_json_error(i, "indicator"))
        validation = ""
        s_tags = ""
        pulse_count = 0
        
        tags = []

        for idx in i["validation"]:
          temp_validation = check_json_error(idx, "name")
          
          if temp_validation != None and temp_validation != "":
            validation = temp_validation

        asn = check_json_error(i, "asn")
        code = check_json_error(i, "country_code")

        pulse_info = check_json_error(i, "pulse_info")
        
        if pulse_info != None and pulse_info != "":
          pulse_count = check_json_error(pulse_info, "count")
          tags = AlienVault.get_pulse_tags(pulse_info)

          temp_tags = tags.sort(reverse=True)
          if temp_tags != None:
            tags = temp_tags

        for tg in range(len(tags)):
          if tg > ALIEN_VAULT_MAX_TAGS:
            break
          
          if tg == len(tags)-1:
            s_tags += AlienVault.get_highlighted_text(tags[tg])
          else:
            s_tags += AlienVault.get_highlighted_text(tags[tg]) + ","


        table.add_row([ip, validation, asn, code, pulse_count, rep, s_tags])
        rows += 1

    else:
      ind_name = ""
      ind_name_size = 75

      if ind == IndicatorType.Url:
        ind_name = "Url"
      elif ind == IndicatorType.Domain:
        ind_name = "Domain"
      elif ind == IndicatorType.Hash:
        ind_name = "SHA256"
        ind_name_size = 64

      table.field_names = [
        C.f_yellow(ind_name),
        C.f_yellow("Pulses"),
        C.f_yellow("Families"),
        C.f_yellow("tags")
      ]

      table._max_width = {
        C.f_yellow(ind_name): ind_name_size,
        C.f_yellow("Pulses"): 3,
        C.f_yellow("Families"): 25,
        C.f_yellow("tags"): 100
      }

      rows = 0
      for key in iocs:
        hash = C.f_green(check_json_error(key, "indicator"))
        pulse_info = check_json_error(key, "pulse_info")

        pulses = check_json_error(pulse_info, "pulses")
        pulse_count = C.fd_yellow(check_json_error(pulse_info, "count"))
        
        info = AlienVault.get_pulse_information(pulses)
        families = C.bd_red(C.f_white(info["families"]))
        tags = info["tags"]

        table.add_row([hash, pulse_count, families, tags])
        rows += 1      

    if rows > 0:
      print("\nAlienVault Results")
      print(table)
    else:
      print("Nothing to display")


  # def get_url_quickscan(self, urls):
  #   table = ColorTable()
  #   table.align = "l"
  #   table.field_names = [
  #     C.f_yellow("Hash"),
  #     C.f_yellow("Pulses"),
  #     C.f_yellow("Families"),
  #     C.f_yellow("tags")
  #   ]

  #   table._max_width = {
  #     C.f_yellow("Hash"): 64,
  #     C.f_yellow("Pulses"): 3,
  #     C.f_yellow("Families"): 25,
  #     C.f_yellow("tags"): 100
  #   }

  #   rows = 0
  #   for key in urls:
  #     hash = C.f_green(check_json_error(key, "indicator"))
  #     pulse_info = check_json_error(key, "pulse_info")

  #     pulses = check_json_error(pulse_info, "pulses")
  #     pulse_count = C.fd_yellow(check_json_error(pulse_info, "count"))
      
  #     info = AlienVault.get_pulse_information(pulses)
  #     families = C.bd_red(C.f_white(info["families"]))
  #     tags = info["tags"]

  #     table.add_row([hash, pulse_count, families, tags])
  #     rows += 1
    
  #   if rows > 0:
  #     print(table)
  #   else:
  #     print("Nothing to display")


  # def get_domain_quickscan(self, domains):
  #   table = ColorTable()
  #   table.align = "l"
  #   table.field_names = [
  #     C.f_yellow("Hash"),
  #     C.f_yellow("Pulses"),
  #     C.f_yellow("Families"),
  #     C.f_yellow("tags")
  #   ]

  #   table._max_width = {
  #     C.f_yellow("Hash"): 64,
  #     C.f_yellow("Pulses"): 3,
  #     C.f_yellow("Families"): 25,
  #     C.f_yellow("tags"): 100
  #   }

  #   rows = 0
  #   for key in domains:
  #     hash = C.f_green(check_json_error(key, "indicator"))
  #     pulse_info = check_json_error(key, "pulse_info")

  #     pulses = check_json_error(pulse_info, "pulses")
  #     pulse_count = C.fd_yellow(check_json_error(pulse_info, "count"))
      
  #     info = AlienVault.get_pulse_information(pulses)
  #     families = C.bd_red(C.f_white(info["families"]))
  #     tags = info["tags"]

  #     table.add_row([hash, pulse_count, families, tags])
  #     rows += 1
    
  #   if rows > 0:
  #     print(table)
  #   else:
  #     print("Nothing to display")


  # def get_hash_quickscan(self, hashes: list):
  #   table = ColorTable()
  #   table.align = "l"
  #   table.field_names = [
  #     C.f_yellow("Hash"),
  #     C.f_yellow("Pulses"),
  #     C.f_yellow("Families"),
  #     C.f_yellow("tags")
  #   ]

  #   table._max_width = {
  #     C.f_yellow("Hash"): 64,
  #     C.f_yellow("Pulses"): 3,
  #     C.f_yellow("Families"): 25,
  #     C.f_yellow("tags"): 100
  #   }

  #   rows = 0
  #   for key in hashes:
  #     hash = C.f_green(check_json_error(key, "indicator"))
  #     pulse_info = check_json_error(key, "pulse_info")

  #     pulses = check_json_error(pulse_info, "pulses")
  #     pulse_count = C.fd_yellow(check_json_error(pulse_info, "count"))
      
  #     info = AlienVault.get_pulse_information(pulses)
  #     families = C.bd_red(C.f_white(info["families"]))
  #     tags = info["tags"]

  #     table.add_row([hash, pulse_count, families, tags])
  #     rows += 1
    
  #   if rows > 0:
  #     print(table)
  #   else:
  #     print("Nothing to display")