"""
Secure Password and Passphrase Generator
Uses Python's cryptographically secure 'secrets' module for all entropy collection.
"""

import string
import secrets
from typing import List, Dict, Any, Optional

# Standard character sets
UPPERCASE_CHARS = string.ascii_uppercase
LOWERCASE_CHARS = string.ascii_lowercase
DIGIT_CHARS = string.digits
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Ambiguous characters often confused in print or displays
AMBIGUOUS_CHARS = set("il1Lo0O|'`\"~;:.,")

# Standard eff-long-style compact wordlist for passphrase generation
DICELIGHT_WORDS = [
    "abandon", "ability", "absent", "absorb", "abstract", "academy", "access", "account",
    "achieve", "action", "active", "actor", "adapt", "address", "advance", "advice",
    "afford", "agency", "agenda", "agree", "airport", "album", "alert", "alien",
    "alpha", "alter", "altitude", "amateur", "amber", "anchor", "ancient", "angel",
    "animal", "antenna", "antique", "anvil", "apology", "apple", "apron", "archive",
    "arena", "armor", "arrow", "artist", "aspect", "asset", "assist", "atomic",
    "attack", "attic", "audit", "august", "author", "auto", "autumn", "avatar",
    "avenue", "avocado", "axis", "badge", "bagel", "balance", "balcony", "ballot",
    "bamboo", "banana", "banner", "barber", "bargain", "barrel", "barrier", "basement",
    "basket", "battery", "beacon", "beauty", "become", "bee", "before", "begin",
    "behave", "behind", "belief", "belong", "benefit", "berry", "beyond", "bicycle",
    "binder", "biology", "bird", "bison", "bitter", "blade", "blanket", "blast",
    "blender", "blossom", "blueberry", "board", "boil", "bold", "bonus", "border",
    "bounce", "bracket", "brain", "branch", "brave", "breeze", "brick", "bridge",
    "bright", "bronze", "bubble", "budget", "buffalo", "bullet", "bundle", "bunker",
    "butter", "cabin", "cable", "cactus", "cadet", "cafe", "calendar", "calm",
    "camel", "camera", "camp", "canary", "candle", "cannon", "canvas", "canyon",
    "capable", "capital", "captain", "caravan", "carbon", "card", "cargo", "carpet",
    "carrier", "carrot", "castle", "casual", "catalog", "catch", "cater", "ceiling",
    "celery", "cement", "census", "century", "cereal", "chain", "chalk", "champion",
    "channel", "chapter", "charge", "chariot", "charity", "charm", "chart", "chatter",
    "cheese", "chef", "cherry", "chest", "chief", "chimney", "choice", "chord",
    "chrome", "chronic", "chunk", "cider", "cigar", "cinema", "circle", "citizen",
    "citrus", "civic", "civil", "claim", "clamp", "clarity", "clash", "classic",
    "claw", "clean", "clerk", "clever", "cliff", "climate", "climb", "clinic",
    "clip", "clock", "clone", "cloth", "cloud", "clover", "cluster", "coach",
    "coast", "cobra", "coffee", "coil", "coin", "collector", "colony", "column",
    "combine", "comet", "comfort", "command", "compass", "complex", "compose", "concise",
    "concrete", "conduct", "conifer", "connect", "consent", "consist", "contact", "contain",
    "content", "context", "contour", "control", "converge", "convey", "cookie", "copper",
    "coral", "corridor", "cosmos", "cotton", "couch", "counsel", "count", "country",
    "courage", "cousin", "cradle", "craft", "crane", "crater", "crayon", "creek",
    "cricket", "crisp", "cross", "crown", "crucial", "cruise", "crystal", "cube",
    "culture", "cupboard", "curious", "current", "curtain", "cushion", "custom", "cycle"
]

class PasswordGenerationError(ValueError):
    """Raised when password generation parameters are invalid or contradictory."""
    pass

def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_exclude: Optional[str] = None,
    guarantee_each_type: bool = True
) -> str:
    """
    Generates a cryptographically secure random password using secrets.SystemRandom.
    
    :param length: Total length of the password (range: 4 to 256).
    :param include_uppercase: Whether to include uppercase letters [A-Z].
    :param include_lowercase: Whether to include lowercase letters [a-z].
    :param include_digits: Whether to include decimal numbers [0-9].
    :param include_symbols: Whether to include symbols and punctuation.
    :param exclude_ambiguous: If True, filters out easily confused characters (e.g. 0/O, 1/l/I).
    :param custom_exclude: String containing specific characters to exclude.
    :param guarantee_each_type: Ensures at least one character from each active character pool.
    :return: Generated password string.
    """
    if length < 4:
        raise PasswordGenerationError("Password length must be at least 4 characters.")
    if length > 256:
        raise PasswordGenerationError("Password length exceeds maximum limit of 256 characters.")

    # Build character categories
    categories = []
    
    if include_uppercase:
        chars = UPPERCASE_CHARS
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        if custom_exclude:
            chars = "".join(c for c in chars if c not in custom_exclude)
        if chars:
            categories.append(chars)

    if include_lowercase:
        chars = LOWERCASE_CHARS
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        if custom_exclude:
            chars = "".join(c for c in chars if c not in custom_exclude)
        if chars:
            categories.append(chars)

    if include_digits:
        chars = DIGIT_CHARS
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        if custom_exclude:
            chars = "".join(c for c in chars if c not in custom_exclude)
        if chars:
            categories.append(chars)

    if include_symbols:
        chars = SYMBOL_CHARS
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        if custom_exclude:
            chars = "".join(c for c in chars if c not in custom_exclude)
        if chars:
            categories.append(chars)

    if not categories:
        raise PasswordGenerationError("No characters available. Enable at least one character set.")

    full_pool = "".join(categories)
    if not full_pool:
        raise PasswordGenerationError("All characters were excluded. Adjust exclusions.")

    if guarantee_each_type and length < len(categories):
        raise PasswordGenerationError(
            f"Requested length ({length}) is smaller than the number of active character categories ({len(categories)})."
        )

    rng = secrets.SystemRandom()
    password_chars = []

    # Guarantee at least one character from each selected category
    if guarantee_each_type:
        for cat in categories:
            password_chars.append(rng.choice(cat))

    # Fill remaining characters from the entire unified pool
    remaining_len = length - len(password_chars)
    for _ in range(remaining_len):
        password_chars.append(rng.choice(full_pool))

    # Cryptographically secure in-place Fisher-Yates shuffle
    rng.shuffle(password_chars)

    return "".join(password_chars)

def generate_multiple_passwords(count: int = 5, **kwargs) -> List[str]:
    """Generates a batch of distinct secure passwords."""
    if count < 1 or count > 50:
        raise PasswordGenerationError("Count must be between 1 and 50.")
    return [generate_password(**kwargs) for _ in range(count)]

def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """
    Generates a memorable Diceware-style passphrase.
    e.g.: 'Breeze-Canary-Cosmos-Anchor-42'
    """
    if word_count < 2 or word_count > 12:
        raise PasswordGenerationError("Word count must be between 2 and 12.")
        
    rng = secrets.SystemRandom()
    words = [rng.choice(DICELIGHT_WORDS) for _ in range(word_count)]
    
    if capitalize:
        words = [w.capitalize() for w in words]
        
    if include_number:
        # Append a 2-digit number (10..99)
        num = str(rng.randint(10, 99))
        words.append(num)
        
    return separator.join(words)
