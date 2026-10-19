# Human-readable rendering of a SHA-256 public-key fingerprint (see
# crypto_utils.get_public_key_fingerprint()) as a short sequence of common
# English words instead of 64 hex characters - the same idea as the classic
# "PGP Word List", used everywhere this project asks an administrator to
# compare a fingerprint out-of-band with another human (client/server
# registration - TECHNICAL_REFERENCE.md Section 2.3.4/2.4.1 - and the admintui Onboarding/
# Clients tabs). Two people reading "otter maple copper ..." to each other
# over the phone catch a mismatch far more reliably than two people reading
# 64 hex digits, where every "b"/"d" or "1"/"7" is a coin flip.
#
# One word per byte, direct index (0-255) - deliberately not a bit-packed
# scheme (e.g. BIP39's 11-bits-per-word encoding), so there is no risk of a
# padding/bit-alignment bug: each of a SHA-256 fingerprint's 32 bytes maps to
# exactly one word, independent of every other byte, and the whole 256-bit
# fingerprint is represented losslessly (never truncated) - weakening the
# comparison to fewer bits would also weaken its ability to catch a
# substituted key (see issue.md's replay/impersonation analysis).
#
# WORDLIST was hand-picked for this project: short (3-8 letters), common
# enough to read on sight, and deliberately avoiding known-confusable
# homophone pairs (e.g. no "sun"/"son", "bear"/"bare", "one"/"won") and
# digit-words (no "one".."nine"/"ten") that could be misheard as numbers
# rather than as fingerprint words.

WORDLIST = (
    "acorn", "adder", "alloy", "almond", "amber", "anchor", "anvil", "apple",
    "apron", "arrow", "ashtray", "aspen", "auger", "badger", "bagel", "bamboo",
    "banjo", "barley", "barrel", "basil", "beacon", "beagle", "beaver", "beetle",
    "bellow", "berry", "birch", "biscuit", "bison", "blanket", "bolt", "bonnet",
    "boulder", "bramble", "brass", "brick", "bridle", "bronze", "brook", "buckle",
    "buffalo", "bugle", "bunker", "burlap", "cactus", "camel", "candle", "canoe",
    "canyon", "carbon", "cargo", "carrot", "cedar", "cellar", "chalk", "cherry",
    "chestnut", "chimney", "chisel", "cider", "cinder", "clamp", "clover", "cobalt",
    "cobra", "cocoa", "compass", "condor", "copper", "coral", "cottage", "cougar",
    "cradle", "cranberry", "cranky", "crater", "cricket", "crimson", "crocus", "crystal",
    "cupboard", "dagger", "daisy", "damson", "dandelion", "diesel", "dolphin", "domino",
    "donkey", "dragon", "drift", "eagle", "ebony", "eclipse", "elbow", "elk",
    "elm", "ember", "emerald", "empire", "engine", "falcon", "feather", "fennel",
    "fern", "ferry", "fiddle", "finch", "fjord", "flannel", "flint", "forest",
    "forge", "fossil", "fountain", "fox", "frigate", "frost", "garnet", "gazelle",
    "gecko", "geyser", "ginger", "glacier", "goblet", "goose", "gopher", "gorge",
    "gorilla", "granite", "grasshopper", "gravel", "griffin", "grotto", "guitar", "gumbo",
    "hamlet", "hamster", "harbor", "harness", "hatchet", "hawk", "hazel", "heron",
    "hickory", "holly", "hornet", "hyena", "iguana", "indigo", "iris", "island",
    "ivory", "jackal", "jade", "jaguar", "jasmine", "jester", "jetty", "jigsaw",
    "jungle", "juniper", "kelp", "kettle", "kiln", "kiosk", "kite", "koala",
    "ladder", "lagoon", "lantern", "larch", "lark", "latch", "lava", "lentil",
    "leopard", "lilac", "linen", "lizard", "llama", "lobster", "locust", "lotus",
    "lumber", "lynx", "magpie", "mallet", "mammoth", "mandolin", "mango", "mantis",
    "maple", "marble", "marlin", "marsh", "meadow", "melon", "meteor", "millet",
    "minnow", "mirage", "mitten", "moccasin", "molasses", "mongoose", "monsoon", "moose",
    "moth", "mustard", "nectar", "needle", "newt", "nickel", "nutmeg", "oasis",
    "oatmeal", "octopus", "olive", "onion", "onyx", "opal", "orchard", "orchid",
    "osprey", "otter", "outpost", "oxcart", "paddle", "panda", "pansy", "papaya",
    "parsley", "peacock", "peanut", "pebble", "pecan", "pelican", "pepper", "petal",
    "pheasant", "pickle", "pigeon", "pillar", "pinecone", "pistachio", "plateau", "plum",
    "pretzel", "prism", "pumice", "pyramid", "quail", "quartz", "quilt", "quiver",
)

assert len(WORDLIST) == 256, f"WORDLIST must have exactly 256 entries, has {len(WORDLIST)}"
assert len(set(WORDLIST)) == 256, "WORDLIST must not contain duplicate entries"


def fingerprint_to_word_list(fingerprint_hex: str):
    """Convert a hex-encoded SHA-256 fingerprint (as returned by
    crypto_utils.get_public_key_fingerprint()) into a list of 32 words, one
    per byte, in the same order as the original bytes. Raises ValueError if
    `fingerprint_hex` isn't valid hex or isn't exactly 32 bytes (256 bits) -
    i.e. isn't actually a SHA-256 digest."""
    try:
        fingerprint_bytes = bytes.fromhex(fingerprint_hex)
    except ValueError as e:
        raise ValueError(f"'{fingerprint_hex}' is not valid hex: {e}")
    if len(fingerprint_bytes) != 32:
        raise ValueError(f"expected a 32-byte (SHA-256) fingerprint, got {len(fingerprint_bytes)} bytes")
    return [WORDLIST[b] for b in fingerprint_bytes]


def format_fingerprint_words(fingerprint_hex: str, words_per_line: int = 6) -> str:
    """Render a fingerprint as newline-grouped, 1-indexed words, e.g.:

        1:acorn   2:maple   3:otter   4:cedar   5:finch   6:opal
        7:garnet  8:cobra   ...

    The numbering matters more than it might look: it lets two people
    reading over the phone say "word twelve" instead of losing their place
    partway through 32 words - the exact failure mode plain unnumbered hex
    or word output both have.
    """
    words = fingerprint_to_word_list(fingerprint_hex)
    numbered = [f"{i}:{word}" for i, word in enumerate(words, start=1)]
    lines = []
    for i in range(0, len(numbered), words_per_line):
        lines.append("  ".join(numbered[i:i + words_per_line]))
    return "\n".join(lines)
