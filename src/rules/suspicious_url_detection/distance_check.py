
from legit_domains import LEGIT_DOMAINS
import Levenshtein


def normalize_domain_names(domain: str) -> str:
    #remove empty spaces and change all to lowercase
    domain_name = domain.lower().strip()

    if domain_name.startswith("www."):
        domain_name = domain_name[4:]
    
    if domain_name.endswith("."):
        domain_name = domain_name[:-1]

    return domain_name

def distance_check(sender_domain: str, legit_domains: set[str], max_distance: int=2):
        
        sender_domain_name = normalize_domain_names(sender_domain)

        #given a sender domain and legit domain names, which one matches each other the best
        best_match = None
        best_distance = None

        for domain in legit_domains:
             
            legit_domain_name = normalize_domain_names(domain)

            if abs(len(sender_domain_name) - len(legit_domain_name)) > max_distance: #compare the length of domains, skip if the length is greater than max_distance threshold
                 continue
            
            distance = Levenshtein.distance(sender_domain_name, legit_domain_name)
            
            if best_distance is None or distance < best_distance:
                 best_distance = distance
                 best_match = legit_domain_name

                 if best_distance == 0:  #exact match
                      break

                     
        if best_distance is not None and 1 <= best_distance <= max_distance:    #Suspicious if close but not exact 
            return(False, f"best match: {best_match}, distance check: {best_distance}")
        
        elif best_distance is not None and best_distance > max_distance:        #Pass the threshold but return the closest match
            return(False, f"best match: {best_match}, distance check: {best_distance}")
                    
        else:
            return(True, f"best match: {best_match}, distance check: {best_distance}")
        
print(distance_check("yahoo.com", LEGIT_DOMAINS))       
print(distance_check("paypal.com", LEGIT_DOMAINS))






        


