from src.shared import load_config, parse_config_file, THREAT_FOX_KEY, THREAT_FOX_DISABLED, SUPRESS_WARNINGS
from src.shared import Colour as C, Item, Dbg, check_json_error, extract_date
import requests, enum, json, time
from prettytable.colortable import ColorTable
from datetime import datetime

class TfxApiErr(enum.Enum):
  Nan = 0
  Ok = 1
  No_Result = 2
  No_Json = 3
  Illegal_Hash = 4
  Illegal_Search_Term = 5


class QueryType(enum.Enum):
  Hash = 0
  Url = 1
  Ip = 3


class ThreatFox(Dbg):
  
  BASE_PTH_QUERY_IOC = "https://threatfox-api.abuse.ch/api/v1/"

  JSON_HDR = ("accept", "application/json")
  CNT_LEN_HDR = "content-length"

  def init(self):
    '''Reads the config file and parses the json to retrieve the VT API key.'''
    data_pair = load_config()
    data = data_pair[0]
    key = parse_config_file(data[THREAT_FOX_KEY])
    disable_tfx = parse_config_file(data[THREAT_FOX_DISABLED])
    warnings = parse_config_file(data[SUPRESS_WARNINGS])

    if key != None:
      self.api_key[1] = key

    if disable_tfx != None:
      self.disabled = bool(disable_tfx)

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
    self.api_key = ["x-apikey", ""]


  def query_ioc(self, ioc: str, qtype=QueryType.Ip):
    '''Function queries the Threat Fox API for IOCs such as Urls, domains, hashes and IP addresses'''
    base_url = self.BASE_PTH_QUERY_IOC
    
    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.CNT_LEN_HDR: str(len(ioc))
    }

    query_type = "search_ioc"
    search = "search_term"

    if qtype == QueryType.Hash:
      query_type = "search_hash"
      search = "hash"

    payload = {
      "query": query_type,
      search: ioc
    }

    start = time.time()
    response = requests.post(base_url, headers=header, json=payload)

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")
    
    text = response.text
    return text


  def collect_ioc_responses(self, iocs: list, qtype=QueryType.Ip):
    '''Function reads a list of IOCs and then queries each of them on the ThreatFox API and collects the json response to each.'''
    responses = []
    err = TfxApiErr.Nan
    
    for i in iocs:
      resp = self.query_ioc(i, qtype)
      err = self.handle_api_error(resp)

      if err == TfxApiErr.Ok or err == TfxApiErr.Nan:
        self.dprint(f"Adding item with err {err} to response list")
        data = json.loads(resp)
        responses.append(data)
    
    return responses


  def get_error_code(err: str):
    '''Function checks the message received from the API response and returns the corresponding TfxApiErr enum.'''
    if err == "ok":
      return TfxApiErr.Ok
    elif err == "no_result":
      return TfxApiErr.No_Result
    elif err == "no_json":
      return TfxApiErr.No_Json
    elif err == "illegl_hash":
      return TfxApiErr.Illegal_Hash
    elif err == "illegal_search_term":
      return TfxApiErr.Illegal_Search_Term
    else:
      return TfxApiErr.Nan


  def handle_api_error(self, data):
    '''Function checks each json response and returns the corresponding TfxApiErr anum as a result.
    As most IOCs from the ThreatFox API will not return a result, most error messages will not be displayed.'''
    err = TfxApiErr.Nan

    if self.raw_json == True:
      print(data)
      exit(1)

    try:
      dt = json.loads(data)
      error = dt["query_status"]

      if len(error) > 0:
        err = ThreatFox.get_error_code(error)
        msg = dt["data"]
        if err != TfxApiErr.Ok and err != TfxApiErr.No_Result and err != TfxApiErr.Nan:
          print(f"{C.f_red('Error')}: ({C.f_green('ThreatFox')}) {C.fd_yellow(msg)}")

        self.dprint(f"({C.f_green('ThreatFox')}) {C.fd_yellow(msg)}")

      return err
    except KeyError:
      return err


  def get_tag_contents(tags: list):
    '''Function gets the contents of the tags json key and retrieves the string stored in the array.'''
    out = ""

    try:

      for i in tags:
        if len(tags) > 1:
          out += i + ","
        else:
          out += i
    except TypeError:
      return out

    if len(out) > 1 and out[len(out)-1] == ",":
      out = out[0:len(out)-1]
    
    return out


  def get_ioc_quickscan(self, iocs: list):
    '''Function takes a list of the IOCs as json responses and displays the information in a nice table.'''

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("ioc"),
      C.f_yellow("type"),
      C.f_yellow("threat"),
      C.f_yellow("malware"),
      C.f_yellow("Confidence"),
      C.f_yellow("First Seen"),
      C.f_yellow("Last Seen"),
      C.f_yellow("Reporter"),
      C.f_yellow("tags")
    ]

    table._max_width = {
      C.f_yellow("ioc"): 60,
      C.f_yellow("type"): 10,
      C.f_yellow("threat"): 20,
      C.f_yellow("malware"): 25,
      C.f_yellow("Confidence"): 6,
      C.f_yellow("First Seen"): 25,
      C.f_yellow("Last Seen"): 25,
      C.f_yellow("Reporter"): 15,
      C.f_yellow("tags"): 20
    }

    if len(iocs) < 1:
      return
    
    malware_samples = []

    rows = 0
    for i in iocs:
      data = i["data"]

      for idx in data:
        confidence = 0
        
        ioc = C.f_green(check_json_error(idx, "ioc"))
        t_ioc = check_json_error(idx, "ioc_type")
        threat = check_json_error(idx, "threat_type")
        malware = check_json_error(idx, "malware_printable")
        conf = check_json_error(idx, "confidence_level")
        first = check_json_error(idx, "first_seen")
        last = check_json_error(idx, "last_seen")
        reporter = check_json_error(idx, "reporter")
        tag = check_json_error(idx, "tags")
        samples = check_json_error(idx, "malware_samples")

        if samples != None and samples != "":
          malware_samples.append(samples)

        tags = ""
        if tag != None:
          tags = ThreatFox.get_tag_contents(tag)
        
        temp_first = ""
        temp_last = ""

        if first != "" and first != None:
          temp_first = extract_date(first)
          
        if last != "" and last != None:
          temp_last = extract_date(last)

        if temp_first != None:
          first = temp_first
        
        if temp_last != None:
          last = temp_last

        if conf != "":
          confidence = int(conf)

        if confidence < 20:
          confidence = C.f_blue(confidence)
        elif confidence > 20 and confidence < 40:
          confidence = C.f_green(confidence)
        elif confidence > 40 and confidence < 70:
          confidence = C.fd_yellow(confidence)
        elif confidence > 70 and confidence < 90:
          confidence = C.f_red(confidence)
        elif confidence > 90:
          confidence = C.b_red(C.f_white(confidence))

        if reporter == "abuse_ch":
          reporter = C.f_red(reporter)

        if first == None or first == "":
          first = "Never"
        
        if last == None or last == "":
          last = "Never"

        table.add_row([ioc, t_ioc, threat, malware, confidence, first, last, reporter, tags])
        rows += 1

    if rows > 0:
      print("\nThreatFox IOC Results")
      print(table)
    else:
      print("Nothing to display")

    sample_table = ColorTable()
    sample_table.align = "l"
    sample_table.field_names = [
      C.f_yellow("Date"),
      C.f_yellow("SHA256"),
      C.f_yellow("Link")
    ]

    sample_table._max_width = {
      C.f_yellow("Date"): 25,
      C.f_yellow("SHA256"): 68,
      C.f_yellow("Link"): 100,
    }
    
    sample_rows = 0
    for i in malware_samples:
      
      for idx in i:
        date = check_json_error(idx, "time_stamp")
        hash = check_json_error(idx, "sha256_hash")
        link = check_json_error(idx, "malware_bazaar")

        sample_table.add_row([date, hash, link])
        sample_rows += 1

    if sample_rows > 0:
      print("\nThreatFox malware samples")
      print(sample_table)