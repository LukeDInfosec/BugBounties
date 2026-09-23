#!/usr/bin/env python3
"""Scope engine tests.

Every case here is a way a real framework has let a tester scan something they
should not have. If one of these regresses, the framework is unsafe.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from bbhunter.scope import Scope, Decision, registrable_domain, normalise_host

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n        got {got!r}, wanted {want!r}")


def decides(scope, asset, want, label=None):
    verdict = scope.classify(asset)
    check(label or f"{asset} -> {want.value}", verdict.decision, want)


scope = Scope.from_lines(
    include_text="""
        *.acme.com
        acme.co.uk
        45.33.32.0/24
        https://portal.partner.test/app/
        api-*.edge.acme.com
    """,
    exclude_text="""
        *.internal.acme.com
        legacy.acme.com
        45.33.32.55
    """,
)

print("== in scope ==")
decides(scope, "acme.com", Decision.ALLOW)
decides(scope, "api.acme.com", Decision.ALLOW)
decides(scope, "deep.nested.api.acme.com", Decision.ALLOW)
decides(scope, "ACME.COM", Decision.ALLOW, "uppercase is normalised")
decides(scope, "acme.com.", Decision.ALLOW, "trailing dot is normalised")
decides(scope, "https://api.acme.com/x?y=1", Decision.ALLOW, "URL on an in-scope host")
decides(scope, "45.33.32.10", Decision.ALLOW, "address inside the CIDR")
decides(scope, "api-eu.edge.acme.com", Decision.ALLOW, "glob match")

print("== the substring bug, which is how people scan strangers ==")
decides(scope, "notacme.com", Decision.OBSERVE, "notacme.com must NOT match acme.com")
decides(scope, "acme.com.evil.test", Decision.OBSERVE, "suffix-append must not match")
decides(scope, "evilacme.com", Decision.OBSERVE, "prefix-append must not match")
decides(scope, "acme.co.uk.attacker.test", Decision.OBSERVE, "ccTLD suffix-append")

print("== exclude beats include, always ==")
decides(scope, "legacy.acme.com", Decision.DENY)
decides(scope, "vpn.internal.acme.com", Decision.DENY)
decides(scope, "internal.acme.com", Decision.DENY)
decides(scope, "45.33.32.55", Decision.DENY, "excluded address inside an included CIDR")

print("== userinfo smuggling ==")
decides(scope, "https://api.acme.com@evil.test/", Decision.OBSERVE,
        "host is evil.test, not api.acme.com")
decides(scope, "https://evil.test/?x=https://api.acme.com", Decision.OBSERVE,
        "in-scope host in the query string is not the host")

print("== homoglyphs ==")
decides(scope, "аcme.com", Decision.OBSERVE, "Cyrillic a must not match ASCII acme.com")
decides(scope, "xn--cme-7cd.com", Decision.OBSERVE, "punycode of the homoglyph")

print("== private and metadata addresses are denied before any rule ==")
for addr in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.4.2",
             "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0",
             "100.100.100.200", "192.0.0.192",
             "203.0.113.9", "198.51.100.4", "192.0.2.1", "100.64.0.1"):
    decides(scope, addr, Decision.DENY, f"{addr} blocked")
decides(scope, "localhost", Decision.DENY)
decides(scope, "foo.localhost", Decision.DENY)

private_ok = Scope.from_lines(include_text="10.0.0.0/8", allow_private=True)
decides(private_ok, "10.0.0.5", Decision.ALLOW, "internal testing when explicitly enabled")

print("== URL prefix rules ==")
decides(scope, "https://portal.partner.test/app/admin", Decision.ALLOW, "under the prefix")
decides(scope, "https://portal.partner.test/other", Decision.OBSERVE, "outside the prefix")
decides(scope, "http://portal.partner.test/app/", Decision.OBSERVE, "scheme must match")

print("== glob respects label boundaries ==")
decides(scope, "api-eu.internal.edge.acme.com", Decision.ALLOW,
        "under *.acme.com; the exclude is *.internal.acme.com, which this is not under")
glob_only = Scope.from_lines(include_text="api-*.edge.test")
decides(glob_only, "api-eu.edge.test", Decision.ALLOW)
decides(glob_only, "api-eu.sub.edge.test", Decision.OBSERVE, "* does not cross a dot")

print("== malformed input fails closed ==")
for bad in ("", "   ", "..", "-bad-.com", "a" * 300 + ".com", "ht!tp://x",
            "http://", "https://[::", "999.999.999.999"):
    verdict = scope.classify(bad)
    check(f"{bad[:24]!r} denied or observed",
          verdict.decision in (Decision.DENY, Decision.OBSERVE), True)

print("== registrable domain / public suffix awareness ==")
check("acme.co.uk", registrable_domain("api.shop.acme.co.uk"), "acme.co.uk")
check("acme.com", registrable_domain("a.b.c.acme.com"), "acme.com")
check("github.io sibling", registrable_domain("luke.github.io"), "luke.github.io")
check("s3 sibling", registrable_domain("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com")

print("== DNS scope does not bridge to IP scope ==")
dns_only = Scope.from_lines(include_text="*.acme.com")
decides(dns_only, "93.184.216.34", Decision.OBSERVE,
        "an address an in-scope host resolves to is NOT automatically in scope")

print("== distance accounting ==")
v = dns_only.classify("cdn.other.test", parent_distance=0)
check("distance 1 from an in-scope parent", (v.decision, v.distance),
      (Decision.OBSERVE, 1))
reach1 = Scope.from_lines(include_text="*.acme.com", max_distance=1)
v = reach1.classify("cdn.other.test", parent_distance=0)
check("max_distance 1 allows one hop", (v.decision, v.distance), (Decision.ALLOW, 1))
v = reach1.classify("far.other.test", parent_distance=2)
check("but not three hops", v.decision, Decision.OBSERVE)

print("== the input gate ==")
discovered = ["api.acme.com", "legacy.acme.com", "notacme.com",
              "127.0.0.1", "shop.acme.com", "10.1.1.1"]
allowed, observed, denied = scope.partition(discovered)
check("allowed set", sorted(allowed), ["api.acme.com", "shop.acme.com"])
check("observed set", sorted(observed), ["notacme.com"])
check("denied count", len(denied), 3)
check("filter_allowed matches partition",
      sorted(scope.filter_allowed(discovered)), sorted(allowed))

print("== bare domain children toggle ==")
strict = Scope.from_lines(include_text="acme.com", bare_domain_includes_children=False)
decides(strict, "acme.com", Decision.ALLOW, "apex itself")
decides(strict, "api.acme.com", Decision.OBSERVE, "children excluded when told to")

print("== fingerprint is stable and rule-sensitive ==")
a = Scope.from_lines(include_text="*.acme.com", exclude_text="x.acme.com")
b = Scope.from_lines(include_text="*.acme.com", exclude_text="x.acme.com")
c = Scope.from_lines(include_text="*.acme.com")
check("same rules, same fingerprint", a.fingerprint(), b.fingerprint())
check("different rules, different fingerprint", a.fingerprint() != c.fingerprint(), True)

print("== explain is readable ==")
text = scope.explain("legacy.acme.com")
check("explain names the decision", "BLOCKED" in text, True)
check("explain says no packets", "no packets" in text, True)

print()
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
