

from pathlib import Path


def normalize(domain: str) -> str:
    d = domain.lower().strip()
    if d.startswith("www."):
        d = d[4:]
    if d.endswith("."):
        d = d[:-1]
    return d


def load_txt(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")

    domains: set[str] = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        domains.add(normalize(line))

    return domains


def main():
    base = Path(__file__).parent

    txt_file = base / "static" / "whitelist_domain.txt"
    out_file = base / "legit_domains_generated.py"

    domains = load_txt(txt_file)

    content = (
        "# Auto-generated. Do NOT edit manually.\n\n"
        "LEGIT_DOMAINS = {\n"
    )

    for d in sorted(domains):
        content += f"    {d!r},\n"

    content += "}\n"

    out_file.write_text(content, encoding="utf-8")

    print(f"Generated {out_file}")
    print(f"Total domains: {len(domains)}")


if __name__ == "__main__":
    main()


















