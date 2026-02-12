# from .legit_domains_generated import LEGIT_DOMAINS
# from src.rules.feat.generate_legit.legit_domains_generated import LEGIT_DOMAINS
from ..generate_legit.legit_domains_generated import LEGIT_DOMAINS

import Levenshtein, tldextract
import pandas as pd
SCORE_TYPO_DOMAIN = 20
SCORE_SUBDOMAIN_IMPERSONATION = 25


def normalize_domain_names(domain: str) -> str:
    domain_name = str(domain).lower().strip()
    if domain_name.startswith("www."):
        domain_name = domain_name[4:]
    if domain_name.endswith("."):
        domain_name = domain_name[:-1]
    return domain_name


def split_domain(domain: str):
    extract = tldextract.extract(domain)
    if not extract.domain or not extract.suffix:
        return domain, ""
    registered_domain = f"{extract.domain}.{extract.suffix}"
    sub_domain = extract.subdomain
    return registered_domain, sub_domain


# LEGIT_NORMALIZED = {normalize_domain_names(x) for x in LEGIT_DOMAINS}

# set process faster than list
LEGIT_REGISTERED = set()
LEGIT_BRANDS = set()

for domain in LEGIT_DOMAINS:
    domain_name = normalize_domain_names(domain)
    registered, _sub = split_domain(domain_name)
    LEGIT_REGISTERED.add(registered)

    extract = tldextract.extract(domain_name)
    if extract.domain:
        LEGIT_BRANDS.add(extract.domain)


def score_distance_result(status: str) -> int:
    if status == "IMPERSONATION":
        return SCORE_SUBDOMAIN_IMPERSONATION
    if status == "SUSPICIOUS":
        return SCORE_TYPO_DOMAIN
    return 0


def distance_check(sender_domain: str, legit_set: set[str], max_distance: int = 2):

    sender_domain_name = normalize_domain_names(sender_domain)

    best_match = None
    best_distance = None

    for legit in legit_set:
        legit_domain_name = normalize_domain_names(legit)
        dist = Levenshtein.distance(sender_domain_name, legit_domain_name)

        if best_distance is None or dist < best_distance:
            best_distance = dist
            best_match = legit_domain_name
            if best_distance == 0:
                break

    if best_distance is None or best_distance > max_distance:
        return None, None

    return best_match, best_distance


def enhanced_distance_check(sender_domain: str, legit_domains: set[str], max_distance: int = 2):
    sender_domain_name = normalize_domain_names(sender_domain)
    registered, sub = split_domain(sender_domain_name)

    # Registered domain exact legit?
    if registered in LEGIT_REGISTERED:
        status = "SAFE"
        return True, score_distance_result(status), f"[SAFE] registered='{registered}' exact match"

    # Registered domain close to a legit registered domain?
    reg_match, reg_dist = distance_check(registered, LEGIT_REGISTERED, max_distance=max_distance)
    if reg_dist is not None and 1 <= reg_dist <= max_distance:
        status = "SUSPICIOUS"
        return False, score_distance_result(status), (
            f"[REGISTERED TYPO] '{registered}' ~ '{reg_match}' (dist={reg_dist})"
        )

    # Subdomain impersonation (only when registered is NOT legit)
    if sub:
        # tokenize: a.b-c -> ["a","b","c"]
        tokens = []
        for part in sub.split("."):
            tokens.extend(part.split("-"))

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            #exact brand token in subdomain
            if token in LEGIT_BRANDS:
                status = "IMPERSONATION"
                return False, score_distance_result(status), (
                    f"[SUBDOMAIN BRAND] token '{token}' in '{sender_domain}' (registered='{registered}')"
                )

            # near brand typo in subdomain
            tok_match, tok_dist = distance_check(token, LEGIT_BRANDS, max_distance=max_distance)
            if tok_dist is not None and 1 <= tok_dist <= max_distance:
                status = "IMPERSONATION"
                return False, score_distance_result(status), (
                    f"[SUBDOMAIN TYPO] '{token}' ~ '{tok_match}' (dist={tok_dist}) in '{sender_domain}'"
                )

    # Nothing suspicious
    status = "UNKNOWN"
    return True, score_distance_result(status), f"[PASS] registered='{registered}'"



def get_domain_boolean(sender_domain: str, max_distance: int = 2) -> bool:
    boolean_result, _score, _msg = enhanced_distance_check(sender_domain, LEGIT_DOMAINS, max_distance)
    return boolean_result


def get_domain_score(sender_domain: str, max_distance: int = 2) -> int:
    _boolean_result, score, _msg = enhanced_distance_check(sender_domain, LEGIT_DOMAINS, max_distance)
    return score


def get_domain_message(sender_domain: str, max_distance: int = 2) -> str:
    _boolean_result, _score, msg = enhanced_distance_check(sender_domain, LEGIT_DOMAINS, max_distance)
    return msg



# print(enhanced_distance_check("python.org", LEGIT_DOMAINS, 2))
# print(enhanced_distance_check("pythonn.org", LEGIT_DOMAINS, 2))
# print(enhanced_distance_check("test.paypal.org", LEGIT_DOMAINS, 2))
# print(enhanced_distance_check("gmail.security.xyz", LEGIT_DOMAINS, 2))
# print(enhanced_distance_check("pythno.reference.com", LEGIT_DOMAINS, 2))

# print(get_domain_boolean("python.org"))
# print(get_domain_score("python.org"))
# print(get_domain_message("python.org"))

# print(get_domain_boolean("pythno.reference.com"))
# print(get_domain_score("pythno.reference.com"))
# print(get_domain_message("pythno.reference.com"))



# def score_urls_in_dataset_with_single_test(
#     csv_path: str,
# ):
#     df = pd.read_csv(csv_path)
#     # df[["url_score", "url_boolean"]] = df.apply(extract_score_and_boolean, axis=1)

#     df["enhanced_score"] = df["sender_domain"].apply(get_domain_boolean)

#     print(df[["enhanced_score"]].head(20))
#     # print(df[["url_score", "url_boolean"]].head(20))S
#     # print(df["url_boolean"].value_counts(dropna=False))
#     # print("Any True?", df["url_boolean"].any()) 
#     # print("Highest URL score:", df["url_score"].max())
    
#     return df

# score_urls_in_dataset_with_single_test(csv_path="dataset/email-dataset-figshare/Cleaned/Assassin_cleaned.csv")

