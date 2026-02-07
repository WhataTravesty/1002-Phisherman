from .KeywordRule import KeywordRule

#To make the variable accessable even if inside a function, no need to load and unload Ruleset during batch processing
global KEYWORDS

#Each word stores its own object containing its word and its weightage.
KEYWORDS = {
    # ── Credentials / Authentication ──
    "password": KeywordRule("password", 4),
    "passcode": KeywordRule("passcode", 4),
    "pin": KeywordRule("pin", 3),
    "otp": KeywordRule("otp", 4),
    "2fa": KeywordRule("2fa", 3),
    "mfa": KeywordRule("mfa", 3),
    "login": KeywordRule("login", 3),
    "signin": KeywordRule("signin", 3),
    "sign-in": KeywordRule("sign-in", 3),
    "authenticate": KeywordRule("authenticate", 3),
    "authentication": KeywordRule("authentication", 3),
    "credentials": KeywordRule("credentials", 4),
    "verification": KeywordRule("verification", 3),

    # ── Urgency / Pressure ──
    "urgent": KeywordRule("urgent", 3),
    "immediate": KeywordRule("immediate", 3),
    "immediately": KeywordRule("immediately", 3),
    "asap": KeywordRule("asap", 3),
    "now": KeywordRule("now", 2),
    "today": KeywordRule("today", 2),
    "deadline": KeywordRule("deadline", 3),
    "expires": KeywordRule("expires", 3),
    "expiring": KeywordRule("expiring", 3),
    "final": KeywordRule("final", 2),

    # ── Account / Access ──
    "account": KeywordRule("account", 3),
    "profile": KeywordRule("profile", 2),
    "user": KeywordRule("user", 2),
    "username": KeywordRule("username", 3),
    "access": KeywordRule("access", 2),
    "portal": KeywordRule("portal", 2),
    "dashboard": KeywordRule("dashboard", 2),

    # ── Financial / Payment ──
    "bank": KeywordRule("bank", 4),
    "payment": KeywordRule("payment", 3),
    "billing": KeywordRule("billing", 3),
    "invoice": KeywordRule("invoice", 2),
    "transaction": KeywordRule("transaction", 3),
    "charge": KeywordRule("charge", 3),
    "refund": KeywordRule("refund", 3),
    "tax": KeywordRule("tax", 2),
    "salary": KeywordRule("salary", 2),
    "payroll": KeywordRule("payroll", 3),
    "wire": KeywordRule("wire", 4),
    "transfer": KeywordRule("transfer", 3),
    "crypto": KeywordRule("crypto", 3),
    "wallet": KeywordRule("wallet", 4),

    # ── Threat / Consequence ──
    "suspended": KeywordRule("suspended", 4),
    "locked": KeywordRule("locked", 4),
    "blocked": KeywordRule("blocked", 4),
    "disabled": KeywordRule("disabled", 4),
    "restricted": KeywordRule("restricted", 3),
    "terminated": KeywordRule("terminated", 4),
    "closed": KeywordRule("closed", 3),
    "breach": KeywordRule("breach", 4),
    "compromised": KeywordRule("compromised", 4),
    "unauthorized": KeywordRule("unauthorized", 4),
    "fraud": KeywordRule("fraud", 4),

    # ── Call to Action ──
    "click": KeywordRule("click", 2),
    "open": KeywordRule("open", 2),
    "download": KeywordRule("download", 3),
    "verify": KeywordRule("verify", 3),
    "confirm": KeywordRule("confirm", 3),
    "update": KeywordRule("update", 2),
    "reset": KeywordRule("reset", 3),
    "review": KeywordRule("review", 2),
    "respond": KeywordRule("respond", 2),
    "reply": KeywordRule("reply", 2),

    # ── Legitimacy / Impersonation ──
    "security": KeywordRule("security", 2),
    "support": KeywordRule("support", 2),
    "administrator": KeywordRule("administrator", 3),
    "admin": KeywordRule("admin", 2),
    "helpdesk": KeywordRule("helpdesk", 3),
    "it": KeywordRule("it", 1),
    "compliance": KeywordRule("compliance", 2),
    "legal": KeywordRule("legal", 2),
    "team": KeywordRule("team", 1),

    # ── Delivery / Logistics ──
    "delivery": KeywordRule("delivery", 2),
    "shipment": KeywordRule("shipment", 2),
    "package": KeywordRule("package", 2),
    "courier": KeywordRule("courier", 2),
    "tracking": KeywordRule("tracking", 2),
    "customs": KeywordRule("customs", 2),

    # ── Employment / Internal Lures ──
    "hr": KeywordRule("hr", 2),
    "humanresources": KeywordRule("humanresources", 2),
    "benefits": KeywordRule("benefits", 2),
    "policy": KeywordRule("policy", 2),
    "performance": KeywordRule("performance", 1),
    "bonus": KeywordRule("bonus", 2),
}