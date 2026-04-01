#!/usr/bin/env python3
"""Smart Wordlist Generator — AI-augmented personalized password list builder.

Combines:
  1. OSINT web intelligence (HIBP, social media, public records)
  2. Profile-based generation (CUPP-style: names, dates, pets, cities)
  3. PCFG structural analysis (learned password structures)
  4. Markov chain character-level generation
  5. ISP default key patterns (Livebox, Bbox, Freebox, SFR)
  6. Scoring + ranking by probability

Ported from: metamask-recovery-v4/packages/intelligence/

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Generator
from urllib.parse import quote_plus

sys.path.insert(0, os.path.dirname(__file__))

from lib import Finding, RateLimitedSession, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@dataclass
class TargetProfile:
    """User/target profile for password generation."""
    # Identity
    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    birth_date: str = ""  # DD/MM/YYYY
    # Family
    spouse_name: str = ""
    children_names: list[str] = field(default_factory=list)
    pet_names: list[str] = field(default_factory=list)
    # Location
    city: str = ""
    postal_code: str = ""
    country: str = "FR"
    # Digital
    email: str = ""
    usernames: list[str] = field(default_factory=list)
    phone: str = ""
    company: str = ""
    # Custom
    keywords: list[str] = field(default_factory=list)
    old_passwords: list[str] = field(default_factory=list)
    # WiFi specific
    ssid: str = ""
    bssid: str = ""
    isp: str = ""


# ---------------------------------------------------------------------------
# OSINT Web Collector
# ---------------------------------------------------------------------------

class WebIntelCollector:
    """Collect OSINT data from web sources for wordlist enrichment."""

    def __init__(self, session: RateLimitedSession | None = None):
        self.session = session or RateLimitedSession(rate_limit=2.0)
        self.collected_words: list[str] = []
        self.collected_dates: list[str] = []
        self.breaches: list[dict] = []

    def collect_hibp(self, email: str) -> list[dict]:
        """Check Have I Been Pwned (k-anonymity, no API key needed)."""
        if not email:
            return []
        # Use the password range API with k-anonymity
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            resp = self.session.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10,
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        self.breaches.append({
                            "email": email,
                            "found_in_breaches": True,
                            "occurrence_count": int(count),
                        })
                        log.info("HIBP: %s found in %s breaches", email, count)
                        return self.breaches
        except Exception as exc:
            log.debug("HIBP check failed: %s", exc)
        return []

    def collect_web_keywords(self, profile: TargetProfile, dry_run: bool = False) -> list[str]:
        """Extract keywords from web search results for the target.

        Uses DuckDuckGo Lite (no API key) to gather public info.
        """
        words: list[str] = []
        queries = []

        if profile.first_name and profile.last_name:
            queries.append(f"{profile.first_name} {profile.last_name}")
        if profile.email:
            queries.append(profile.email)
        if profile.company:
            queries.append(f"{profile.first_name} {profile.last_name} {profile.company}")
        if profile.city:
            queries.append(f"{profile.first_name} {profile.last_name} {profile.city}")

        for query in queries[:3]:  # Limit to 3 queries
            if dry_run:
                log.info("[DRY-RUN] Would search: %s", query)
                continue
            try:
                resp = self.session.get(
                    f"https://lite.duckduckgo.com/lite/?q={quote_plus(query)}",
                    timeout=15,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code == 200:
                    text = resp.text
                    # Extract meaningful words (3+ chars, not HTML)
                    clean = re.sub(r"<[^>]+>", " ", text)
                    clean = re.sub(r"[^\w\s@.-]", " ", clean)
                    tokens = clean.split()
                    for token in tokens:
                        t = token.strip()
                        if 3 <= len(t) <= 30 and not t.startswith("http"):
                            words.append(t)
                    log.info("Web search '%s': extracted %d tokens", query, len(tokens))
            except Exception as exc:
                log.debug("Web search failed for '%s': %s", query, exc)
            time.sleep(1.0)  # Be polite

        # Deduplicate + filter noise
        common_noise = {
            "the", "and", "for", "that", "this", "with", "from", "are", "was",
            "has", "have", "not", "but", "all", "can", "had", "her", "one",
            "our", "out", "you", "his", "how", "its", "let", "may", "new",
            "les", "des", "une", "que", "est", "pas", "pour", "dans", "sur",
            "avec", "par", "plus", "sont", "aux", "ont", "ces",
        }
        filtered = [w for w in words if w.lower() not in common_noise]
        # Keep top-50 most frequent
        counter = Counter(filtered)
        top = [word for word, _ in counter.most_common(50)]
        self.collected_words.extend(top)
        return top

    def extract_social_data(self, profile: TargetProfile) -> dict:
        """Extract structured data from social media hints.

        No actual API calls — just parses usernames for patterns.
        """
        data: dict = {"words": [], "dates": [], "numbers": []}
        all_names = [profile.first_name, profile.last_name, profile.nickname,
                     profile.spouse_name, profile.company, profile.city] + \
                    profile.usernames + profile.children_names + profile.pet_names + profile.keywords

        for name in all_names:
            if not name:
                continue
            # Extract sub-tokens
            parts = re.split(r"[._\-\s]+", name)
            data["words"].extend(p for p in parts if len(p) >= 2)
            # Look for embedded numbers
            nums = re.findall(r"\d+", name)
            data["numbers"].extend(nums)
            # Look for dates
            date_matches = re.findall(r"\d{2}[/\-]\d{2}[/\-]\d{4}", name)
            data["dates"].extend(date_matches)

        return data


# ---------------------------------------------------------------------------
# ISP Default Key Generators
# ---------------------------------------------------------------------------

# Orange Livebox default key patterns
_ISP_PATTERNS: dict[str, dict] = {
    "orange": {
        "charset": "0123456789ABCDEF",
        "lengths": [26],
        "note": "Livebox WPA key — 26 hex chars derived from MAC",
    },
    "sfr": {
        "charset": "0123456789abcdef",
        "lengths": [20, 26],
        "note": "SFR Box — 20 or 26 hex chars",
    },
    "bouygues": {
        "charset": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "lengths": [12],
        "note": "Bbox — 12 alphanumeric uppercase",
    },
    "free": {
        "charset": "abcdefghijklmnopqrstuvwxyz0123456789-",
        "lengths": [16],
        "note": "Freebox — 16 lowercase alphanumeric + dash",
    },
}


def generate_isp_candidates(isp: str, bssid: str = "") -> list[str]:
    """Generate ISP-specific default key candidates from BSSID/MAC."""
    candidates: list[str] = []
    info = _ISP_PATTERNS.get(isp.lower(), {})
    if not info:
        return candidates

    # If BSSID available, derive key candidates from MAC bytes
    if bssid:
        mac_clean = bssid.replace(":", "").replace("-", "").upper()
        if len(mac_clean) == 12:
            # Common derivation: last 6 chars of MAC repeated/transformed
            suffix = mac_clean[-6:]
            candidates.append(suffix)
            candidates.append(suffix.lower())
            candidates.append(mac_clean)
            candidates.append(mac_clean.lower())
            # SSID suffix often matches last 4 of MAC
            candidates.append(mac_clean[-4:])

    return candidates


# ---------------------------------------------------------------------------
# PCFG Engine (simplified)
# ---------------------------------------------------------------------------

def _classify_char(c: str) -> str:
    if c.isupper(): return "U"
    if c.islower(): return "L"
    if c.isdigit(): return "D"
    return "S"


def _parse_structure(password: str) -> str:
    """Parse password into structure string like 'U1L5D4S1'."""
    if not password:
        return ""
    segments: list[str] = []
    current_class = _classify_char(password[0])
    length = 1
    for c in password[1:]:
        cls = _classify_char(c)
        if cls == current_class:
            length += 1
        else:
            segments.append(f"{current_class}{length}")
            current_class = cls
            length = 1
    segments.append(f"{current_class}{length}")
    return "".join(segments)


class PCFGEngine:
    """Probabilistic Context-Free Grammar for password generation."""

    def __init__(self):
        self.structures: Counter = Counter()
        self.terminals: dict[str, Counter] = defaultdict(Counter)
        self._trained = False

    def train(self, passwords: list[str]) -> None:
        structure_count = 0
        for pw in passwords:
            if not pw:
                continue
            struct = _parse_structure(pw)
            self.structures[struct] += 1
            structure_count += 1

            # Extract terminal fills
            idx = 0
            for seg in re.findall(r"[ULDS]\d+", struct):
                cls, length_str = seg[0], int(seg[1:])
                value = pw[idx:idx + length_str]
                self.terminals[seg][value] += 1
                idx += length_str

        self._trained = structure_count > 0

    def train_on_profile(self, profile: TargetProfile) -> None:
        """Generate synthetic passwords from profile and train."""
        synthetic = []
        tokens = _profile_tokens(profile)
        suffixes = ["123", "!", "2024", "2025", "2026", "1234", "12345", "#", "!!", "01"]

        for token in tokens[:20]:
            for suffix in suffixes:
                synthetic.append(f"{token}{suffix}")
                synthetic.append(f"{token.capitalize()}{suffix}")
        self.train(synthetic)

    def generate(self, max_candidates: int = 1000) -> Generator[str, None, None]:
        """Generate candidates in probability-descending order."""
        if not self._trained:
            return

        total = sum(self.structures.values())
        sorted_structs = self.structures.most_common(50)

        count = 0
        for struct, freq in sorted_structs:
            if count >= max_candidates:
                return
            segments = re.findall(r"[ULDS]\d+", struct)
            # Get top fills for each segment
            fills_per_seg: list[list[str]] = []
            for seg in segments:
                top_fills = [val for val, _ in self.terminals[seg].most_common(20)]
                if not top_fills:
                    break
                fills_per_seg.append(top_fills)
            else:
                # Product of top fills
                for combo in itertools.islice(itertools.product(*fills_per_seg), 200):
                    candidate = "".join(combo)
                    if 8 <= len(candidate) <= 30:
                        yield candidate
                        count += 1
                        if count >= max_candidates:
                            return

    def get_stats(self) -> dict:
        return {
            "structure_count": len(self.structures),
            "terminal_count": sum(len(v) for v in self.terminals.values()),
        }


# ---------------------------------------------------------------------------
# Markov Model
# ---------------------------------------------------------------------------

class MarkovModel:
    """Character-level Markov chain for password generation."""

    START = "\x02"
    END = "\x03"

    def __init__(self, order: int = 3, smoothing: float = 0.001):
        self.order = order
        self.smoothing = smoothing
        self.transitions: dict[str, Counter] = defaultdict(Counter)
        self.alphabet: set[str] = set()
        self.total_samples = 0

    def train(self, passwords: list[str]) -> None:
        for pw in passwords:
            if not pw:
                continue
            self.total_samples += 1
            self.alphabet.update(pw)

            padded = self.START * self.order + pw + self.END
            for i in range(self.order, len(padded)):
                context = padded[i - self.order:i]
                next_char = padded[i]
                self.transitions[context][next_char] += 1

    def score(self, password: str) -> float:
        """Score a password (0-1, higher = more likely)."""
        if not password:
            return 0.0

        padded = self.START * self.order + password + self.END
        log_prob = 0.0

        for i in range(self.order, len(padded)):
            context = padded[i - self.order:i]
            next_char = padded[i]
            prob = self._get_prob(context, next_char)
            log_prob += math.log(max(prob, 1e-10))

        normalized = log_prob / (len(password) + 1)
        return 1.0 / (1.0 + math.exp(-normalized - 2))

    def generate(self, max_candidates: int = 1000, max_len: int = 20) -> Generator[str, None, None]:
        """Generate candidates from the Markov model."""
        if not self.transitions:
            return

        count = 0
        alpha_list = sorted(self.alphabet)
        if not alpha_list:
            return

        for _ in range(max_candidates * 3):  # Oversample to hit max
            if count >= max_candidates:
                return
            pw = self._generate_one(alpha_list, max_len)
            if pw and 8 <= len(pw) <= max_len:
                yield pw
                count += 1

    def _generate_one(self, alpha_list: list[str], max_len: int) -> str:
        """Generate a single password using the Markov chain."""
        import random
        context = self.START * self.order
        result: list[str] = []

        for _ in range(max_len):
            counts = self.transitions.get(context, {})
            if not counts:
                # Random from alphabet
                c = random.choice(alpha_list)
            else:
                chars = list(counts.keys())
                weights = list(counts.values())
                c = random.choices(chars, weights=weights, k=1)[0]
            if c == self.END:
                break
            result.append(c)
            context = (context + c)[-self.order:]

        return "".join(result)

    def _get_prob(self, context: str, next_char: str) -> float:
        counts = self.transitions.get(context)
        if not counts:
            return self.smoothing
        total = sum(counts.values())
        count = counts.get(next_char, 0)
        return (count + self.smoothing) / (total + self.smoothing * (len(self.alphabet) + 1))

    def get_stats(self) -> dict:
        return {
            "context_count": len(self.transitions),
            "alphabet_size": len(self.alphabet),
            "total_samples": self.total_samples,
        }


# ---------------------------------------------------------------------------
# Profile token extraction
# ---------------------------------------------------------------------------

_COMMON_TRAINING = [
    "Michael123", "Jennifer1990", "David2024!", "Jessica12345",
    "Robert1234", "Sarah2020", "James123!", "password123",
    "letmein2024", "welcome123!", "admin12345", "dragon2024!",
    "Metamask2024!", "Bitcoin123!", "Ethereum2024", "Crypto1234!",
    "Bonjour123", "Soleil2024!", "Amour1234", "France2024",
    "Paris2023!", "Marseille13", "Lyon2024!", "P@ssw0rd123",
    "Qwerty123!", "Azerty2024!", "Abc12345!", "Hello2024!",
]

_SEPARATORS = ["", ".", "_", "-"]
_SUFFIXES = [
    "", "!", "!!", "#", "123", "1234", "12345", "01", "1",
    "2024", "2025", "2026", "2023", "69", "13", "75",
    "@", "!1", "123!", "1234!", "$$",
]
_LEET_MAP = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}


def _profile_tokens(profile: TargetProfile) -> list[str]:
    """Extract all meaningful tokens from the profile."""
    tokens: list[str] = []
    for val in [profile.first_name, profile.last_name, profile.nickname,
                profile.spouse_name, profile.company, profile.city]:
        if val:
            tokens.append(val)
            tokens.append(val.lower())
            tokens.append(val.upper())
            tokens.append(val.capitalize())
    for lst in [profile.children_names, profile.pet_names, profile.keywords, profile.usernames]:
        for val in lst:
            if val:
                tokens.append(val)
                tokens.append(val.lower())
                tokens.append(val.capitalize())
    # Date fragments
    if profile.birth_date:
        parts = re.split(r"[/\-]", profile.birth_date)
        tokens.extend(parts)
        if len(parts) >= 3:
            tokens.append(parts[2])        # year
            tokens.append(parts[2][-2:])   # last 2 digits
            tokens.append(parts[0] + parts[1])  # DDMM
    if profile.phone:
        clean = profile.phone.replace(" ", "").replace("+", "").replace("-", "")
        tokens.append(clean[-4:])  # Last 4 digits
        tokens.append(clean[-6:])
    if profile.postal_code:
        tokens.append(profile.postal_code)
        tokens.append(profile.postal_code[:2])
    if profile.email:
        local = profile.email.split("@")[0]
        tokens.append(local)
        tokens.extend(re.split(r"[._\-+]", local))

    return list(dict.fromkeys(t for t in tokens if t))  # Deduplicate, preserve order


def _leet_transform(word: str) -> str:
    return "".join(_LEET_MAP.get(c.lower(), c) for c in word)


# ---------------------------------------------------------------------------
# Smart Generator (4 phases)
# ---------------------------------------------------------------------------

class SmartGenerator:
    """Main generator — yields candidates in probability-descending order."""

    def __init__(self, profile: TargetProfile, web_words: list[str] | None = None):
        self.profile = profile
        self.tokens = _profile_tokens(profile)
        self.web_words = web_words or []
        self.pcfg = PCFGEngine()
        self.markov = MarkovModel(order=3)
        self._train()

    def _train(self) -> None:
        self.pcfg.train(_COMMON_TRAINING)
        self.pcfg.train(self.profile.old_passwords)
        self.pcfg.train_on_profile(self.profile)
        self.markov.train(_COMMON_TRAINING)
        self.markov.train(self.profile.old_passwords)

    def generate_all(
        self,
        max_phase1: int = 500,
        max_phase2: int = 5000,
        max_phase3: int = 10000,
        max_phase4: int = 50000,
        min_len: int = 8,
        max_len: int = 30,
    ) -> Generator[str, None, None]:
        """Yield candidates across 4 phases, probability-descending."""
        seen: set[str] = set()

        def emit(pw: str) -> str | None:
            if min_len <= len(pw) <= max_len and pw not in seen:
                seen.add(pw)
                return pw
            return None

        # Phase 1: Profile-direct
        count = 0
        for pw in self._phase1():
            if count >= max_phase1:
                break
            r = emit(pw)
            if r:
                yield r
                count += 1

        # Phase 2: PCFG hybrid
        count = 0
        for pw in self.pcfg.generate(max_phase2):
            if count >= max_phase2:
                break
            r = emit(pw)
            if r:
                yield r
                count += 1

        # Phase 3: Markov
        count = 0
        for pw in self.markov.generate(max_phase3, max_len):
            if count >= max_phase3:
                break
            r = emit(pw)
            if r:
                yield r
                count += 1

        # Phase 4: Web-enriched + brute combos
        count = 0
        for pw in self._phase4():
            if count >= max_phase4:
                break
            r = emit(pw)
            if r:
                yield r
                count += 1

    def _phase1(self) -> Generator[str, None, None]:
        """Direct profile candidates — highest probability."""
        # Old passwords + variations
        for pw in self.profile.old_passwords:
            yield pw
            for suffix in _SUFFIXES[:10]:
                yield f"{pw}{suffix}"
            yield _leet_transform(pw)

        # Name combos
        tokens = self.tokens[:30]
        for token in tokens:
            for suffix in _SUFFIXES:
                yield f"{token}{suffix}"
            yield _leet_transform(token)
            # Two tokens
            for token2 in tokens[:10]:
                if token != token2:
                    yield f"{token}{token2}"
                    for sep in _SEPARATORS:
                        yield f"{token}{sep}{token2}"

    def _phase4(self) -> Generator[str, None, None]:
        """Web-enriched + all remaining combos."""
        all_tokens = list(dict.fromkeys(self.tokens + self.web_words))
        for token in all_tokens:
            for suffix in _SUFFIXES:
                yield f"{token}{suffix}"
                yield f"{token.capitalize()}{suffix}"
            yield _leet_transform(token)

        # ISP candidates
        if self.profile.isp:
            for cand in generate_isp_candidates(self.profile.isp, self.profile.bssid):
                yield cand

    def get_stats(self) -> dict:
        return {
            "profile_tokens": len(self.tokens),
            "web_words": len(self.web_words),
            "pcfg": self.pcfg.get_stats(),
            "markov": self.markov.get_stats(),
        }


# ---------------------------------------------------------------------------
# Public API for dashboard
# ---------------------------------------------------------------------------

def build_wordlist(profile_dict: dict, web_search: bool = False, dry_run: bool = False) -> dict:
    """Build a personalized wordlist from a profile dict. Returns stats + path."""
    profile = TargetProfile(**{k: v for k, v in profile_dict.items() if hasattr(TargetProfile, k)})

    web_words: list[str] = []
    if web_search and not dry_run:
        collector = WebIntelCollector()
        web_words = collector.collect_web_keywords(profile, dry_run=dry_run)
        if profile.email:
            collector.collect_hibp(profile.email)

    gen = SmartGenerator(profile, web_words)
    candidates: list[str] = []
    for pw in gen.generate_all():
        candidates.append(pw)

    # Score and sort
    scored = [(pw, gen.markov.score(pw)) for pw in candidates]
    scored.sort(key=lambda x: x[1], reverse=True)

    # Save wordlist
    output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "wordlists", "generated")
    os.makedirs(output_dir, exist_ok=True)
    ts = int(time.time())
    name_slug = re.sub(r"[^a-z0-9]", "", (profile.first_name + profile.last_name).lower())[:20] or "custom"
    output_path = os.path.join(output_dir, f"wordlist-{name_slug}-{ts}.txt")

    with open(output_path, "w") as f:
        for pw, score in scored:
            f.write(pw + "\n")

    return {
        "total_candidates": len(candidates),
        "output_path": output_path,
        "output_filename": os.path.basename(output_path),
        "stats": gen.get_stats(),
        "web_words_count": len(web_words),
        "top_10": [pw for pw, _ in scored[:10]],
    }


# ---------------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--first-name", default="")
    parser.add_argument("--last-name", default="")
    parser.add_argument("--birth-date", default="")
    parser.add_argument("--email", default="")
    parser.add_argument("--city", default="")
    parser.add_argument("--postal-code", default="")
    parser.add_argument("--keywords", nargs="*", default=[])
    parser.add_argument("--old-passwords", nargs="*", default=[])
    parser.add_argument("--web-search", action="store_true", help="Enable web OSINT collection")
    parser.add_argument("--ssid", default="")
    parser.add_argument("--bssid", default="")
    parser.add_argument("--isp", default="", choices=["", "orange", "sfr", "bouygues", "free"])
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    profile = {
        "first_name": args.first_name,
        "last_name": args.last_name,
        "birth_date": args.birth_date,
        "email": args.email,
        "city": args.city,
        "postal_code": args.postal_code,
        "keywords": args.keywords,
        "old_passwords": args.old_passwords,
        "ssid": args.ssid,
        "bssid": args.bssid,
        "isp": args.isp,
    }

    log.info("=" * 60)
    log.info("Smart Wordlist Generator")
    log.info("Profile: %s %s | Web: %s | Dry: %s",
             args.first_name, args.last_name, args.web_search, args.dry_run)
    log.info("=" * 60)

    result = build_wordlist(profile, web_search=args.web_search, dry_run=args.dry_run)

    log.info("Total candidates: %d", result["total_candidates"])
    log.info("Output: %s", result["output_path"])
    log.info("Top 10: %s", result["top_10"])

    findings = [Finding(
        title="Smart wordlist generated",
        severity="info",
        cwe="CWE-521",
        endpoint="local",
        method="LOCAL",
        description=f"Generated {result['total_candidates']} candidates to {result['output_path']}",
        evidence=result,
    )]
    save_findings(findings, "smart-wordlist", getattr(args, "report_dir", "reports"))


if __name__ == "__main__":
    main()
