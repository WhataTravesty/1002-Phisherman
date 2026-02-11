from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set, Any
import re
# from src.rules.feat.generate_legit.legit_domains_generated import LEGIT_DOMAINS
from ..generate_legit.legit_domains_generated import LEGIT_DOMAINS



#this class stores the results of the whitelist check and their justifications
@dataclass(frozen=True)
class WhiteListCheckResults:
    status: str #this is either pass or fail
    reason: str #this states the justification for the status for statistics later
    matched_domain: Optional[str] = None

#this following function will "normalise" the domains
#i.e it standardises them to a format which ensures for consistent analysis 
#per email
#(removing whitespaces, converting to lowercases and remove trailing dots)

domain_regex = re.compile(
     r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$"
)

def is_valid_domain(domain: str) -> bool:
     return bool(domain_regex.fullmatch(domain))

def normalise_domain(domain: Any) -> str:
    if domain is None:
        return ""
    
    d = str(domain).strip().lower()
    return d.rstrip(".")

#this following function will load the whitelist from the white_domain.txt file
#as a Set, this is to help make comparison faster 

def load_legit_domains_whitelist() -> Set[str]:
    wl: Set[str] = set()
    for d in LEGIT_DOMAINS:
          nd = normalise_domain(d)
          if nd:
               wl.add(nd)
    return wl

WHITELIST_SET: Set[str] = load_legit_domains_whitelist()
    
#this following function compares the whitelist with the normalized domains to
# see if they match

def match_whitelist(
        sender_domain: Any,
        whitelist: Set[str],     
) -> Optional[str]:
        
        sender = normalise_domain(sender_domain)

        if not sender:
             return None
        
        if sender in whitelist:
             return sender
        
        for safe_domain in whitelist:
             if sender.endswith("." + safe_domain):
                  return safe_domain

        return None

#this following function is the one running the actual evaluation 
#and returning the results

def run_whitelist_check(
        sender_domain: Any,
        whitelist: Set[str]
) -> WhiteListCheckResults:
        
        sender = normalise_domain(sender_domain)

        if not sender:
             return WhiteListCheckResults(
                  status="Fail",
                  reason="Missing or blank sender domain.",
                  matched_domain=None,
             )
        
        if not is_valid_domain(sender):
             return WhiteListCheckResults(
                  status="Fail",
                  reason="Invalid domain format.",
                  matched_domain=None
             )
          
        matched = match_whitelist(sender, whitelist)
        if matched is not None:
             return WhiteListCheckResults(
                  status="Pass",
                  reason ="Sender domain '{} matched whitelist '{}.".format(sender, matched),
                  matched_domain=matched ,
             )
        
        return WhiteListCheckResults(
             status="Fail",
             reason="Sender domain '{} not found in whitelist.".format(sender),
             matched_domain=None
        )

#return with a False boolean to indicate it failing the check
#used to show in stats 
def triggered_whitelistcheck(result: WhiteListCheckResults) -> int:
     return result.status == "Pass"
       
#add risk score of 25 or 0 depending on the result status
#no need for a range as its just pass or fail
def whitelist_riskscore(result: WhiteListCheckResults) -> int:
     if result.status == "Fail":
          return 25
     elif result.status =="Pass":
          return 0
     else:
          #unknown status so we assume risk anyways
          return 25
     
          
def triggered_reason(result: WhiteListCheckResults) -> str:
     if result.status == "Fail":
          return result.reason
     if result.matched_domain:
          return f"Matched whitelsit domain: {result.matched_domain}"
     return "Whitelist passed"


def get_whitelist_boolean(sender_domain: str) -> bool:
     status = run_whitelist_check(sender_domain, LEGIT_DOMAINS).status
     if status == "Pass":
          return True
     else:
          return False


def get_whitelist_reason(sender_domain: str) -> str:
    reason = run_whitelist_check(sender_domain, LEGIT_DOMAINS).reason
    return reason


def get_whitelist_score(sender_domain: str) -> int:
     status = run_whitelist_check(sender_domain, LEGIT_DOMAINS).status
     if status == "Pass":
          return 0
     else:
          return 25