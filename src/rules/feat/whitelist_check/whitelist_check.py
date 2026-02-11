from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set, Any
import re
# from src.rules.feat.generate_legit.legit_domains_generated import LEGIT_DOMAINS
from ..generate_legit.legit_domains_generated import LEGIT_DOMAINS

#this class stores:
# results of the whitelist check
# their justifications
# and what their matched partner is
@dataclass(frozen=True)
class WhiteListCheckResults:
    status: str #this is either pass or fail
    reason: str #this states the justification for the status for statistics later
    matched_domain: Optional[str] = None

#this following function will "normalise" the domains
#i.e it standardises them to a format which ensures for consistent analysis 
#per email
#(removing whitespaces, converting to lowercases and remove trailing dots)
#regex is used additionally to determine if its follows typical domain name formats
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

# Load and normalize legitimate domains into a set for fast whitelist lookup
def load_legit_domains_whitelist() -> Set[str]:
    wl: Set[str] = set()
    for d in LEGIT_DOMAINS:
          nd = normalise_domain(d)
          if nd:
               wl.add(nd)
    return wl

WHITELIST_SET: Set[str] = load_legit_domains_whitelist()
    
# This function Normalizes the sender domain and determine whether it is
# an exact match or a subdomain of any whitelisted domain

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

# This function Performs a full whitelist validation and matching on a sender domain,
# returning a detailed result for analysis and scoring

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
     

#using the status from the result, this function will return with a boolean value
#which is either True or False based on Pass or Fail 
#this will then be called later on for display in the stats board
def get_whitelist_boolean(sender_domain: str) -> bool:
     status = run_whitelist_check(sender_domain, WHITELIST_SET).status
     if status == "Pass":
          return True
     else:
          return False

#using the results of the reasons from the result, this function will return the reason for why a domain
#passed the whitelist check or failed the whitelist check
def get_whitelist_reason(sender_domain: str) -> str:
    reason = run_whitelist_check(sender_domain, WHITELIST_SET).reason
    return reason

#using the status from the results, this funciton will return with a risk score of either 25 or 0
#dependent on whether the mail was a pass or fail
def get_whitelist_score(sender_domain: str) -> int:
     status = run_whitelist_check(sender_domain, WHITELIST_SET).status
     if status == "Pass":
          return 0
     else:
          return 25