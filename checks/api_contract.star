# Custom ArtBOT Upstream Pinning & Public API Surface Lock (`checks/api_contract.star`).
#
# Prevents custom ArtBOT repositories from importing private modules (`artbot._*`),
# internal submodules (`from artbot.<submodule> import ...`), private underscore-prefixed
# symbols, or symbols not declared in `UPSTREAM_ARTBOT.json`'s `public_api_allowlist`,
# ensuring tagged upstream ArtBOT upgrades never break custom bots.

_PRIVATE_ARTBOT_SUBMODULE_RE = r"^\s*(from\s+artbot\.[a-zA-Z0-9_]+|import\s+artbot\.[a-zA-Z0-9_]+)\b"
_PRIVATE_ARTBOT_SYMBOL_RE = r"^\s*from\s+artbot\s+import\s+[^#\n]*\b_[a-zA-Z0-9_]+"
_HEX40_RE = r"^[0-9a-f]{40}$"

def upstream_artbot_pin_valid(ctx):
    """Verify UPSTREAM_ARTBOT.json pins a valid upstream repo, release tag, and 40-char commit hash."""
    all_files = {f: True for f in ctx.scm.all_files(include_symlinks = True)}
    if "UPSTREAM_ARTBOT.json" not in all_files:
        ctx.emit.finding(
            level = "error",
            message = "UPSTREAM_ARTBOT.json is required in custom ArtBOT repositories to track the upstream tag and commit hash.",
        )
        return

    raw = str(ctx.io.read_file("UPSTREAM_ARTBOT.json"))
    data = json.decode(raw)
    if type(data) != "dict":
        ctx.emit.finding(
            level = "error",
            filepath = "UPSTREAM_ARTBOT.json",
            message = "UPSTREAM_ARTBOT.json must be a JSON object.",
        )
        return

    repo = data.get("upstream_repo", "")
    tag = data.get("upstream_tag", "")
    commit = data.get("upstream_commit", "")
    allowlist = data.get("public_api_allowlist", [])

    if not repo or not repo.endswith("/artbot"):
        ctx.emit.finding(
            level = "error",
            filepath = "UPSTREAM_ARTBOT.json",
            message = "UPSTREAM_ARTBOT.json must specify upstream_repo ending with '/artbot'.",
        )
    if not tag or not tag.startswith("v"):
        ctx.emit.finding(
            level = "error",
            filepath = "UPSTREAM_ARTBOT.json",
            message = "UPSTREAM_ARTBOT.json must specify a versioned upstream_tag starting with 'v' (e.g. 'v0.2.0-artbot').",
        )
    if not commit or not ctx.re.match(_HEX40_RE, str(commit)):
        ctx.emit.finding(
            level = "error",
            filepath = "UPSTREAM_ARTBOT.json",
            message = "UPSTREAM_ARTBOT.json must specify a full 40-character hex upstream_commit SHA.",
        )
    if type(allowlist) != "list" or len(allowlist) == 0:
        ctx.emit.finding(
            level = "error",
            filepath = "UPSTREAM_ARTBOT.json",
            message = "UPSTREAM_ARTBOT.json must declare a non-empty public_api_allowlist.",
        )

def _load_allowlist(ctx):
    all_files = {f: True for f in ctx.scm.all_files(include_symlinks = True)}
    if "UPSTREAM_ARTBOT.json" not in all_files:
        return None
    raw = str(ctx.io.read_file("UPSTREAM_ARTBOT.json"))
    data = json.decode(raw)
    if type(data) != "dict":
        return None
    allowlist = data.get("public_api_allowlist", [])
    if type(allowlist) != "list":
        return None
    return {str(sym): True for sym in allowlist}

def _check_allowlist_tokens(ctx, path, line_no, raw_tokens, allowlist):
    for part in raw_tokens.split(","):
        cleaned = part.strip().lstrip("(").rstrip(")").strip()
        if not cleaned:
            continue
        sym = cleaned.split(" as ")[0].strip()
        if sym and not sym.startswith("_") and sym not in allowlist:
            ctx.emit.finding(
                level = "error",
                filepath = path,
                line = line_no,
                message = "Symbol '%s' imported from `artbot` is not listed in UPSTREAM_ARTBOT.json public_api_allowlist." % sym,
            )

def no_private_artbot_apis(ctx):
    """Forbid importing internal artbot submodules, private underscore-prefixed symbols, or unlisted symbols."""
    allowlist = _load_allowlist(ctx)
    for path in ctx.scm.all_files(glob = "*.py"):
        raw = str(ctx.io.read_file(path))
        in_multiline = False
        for idx, line in enumerate(raw.splitlines()):
            if ctx.re.match(_PRIVATE_ARTBOT_SUBMODULE_RE, line):
                ctx.emit.finding(
                    level = "error",
                    filepath = path,
                    line = idx + 1,
                    message = "Custom ArtBOTs must import only from top-level public `artbot` (`from artbot import ...`), never internal submodules.",
                )
                continue
            if ctx.re.match(_PRIVATE_ARTBOT_SYMBOL_RE, line):
                ctx.emit.finding(
                    level = "error",
                    filepath = path,
                    line = idx + 1,
                    message = "Custom ArtBOTs must not import private underscore-prefixed symbols from `artbot`.",
                )
                continue

            if allowlist == None:
                continue

            code_only = line.split("#")[0].strip()
            if in_multiline:
                if ")" in code_only:
                    before_close = code_only.split(")")[0]
                    _check_allowlist_tokens(ctx, path, idx + 1, before_close, allowlist)
                    in_multiline = False
                else:
                    _check_allowlist_tokens(ctx, path, idx + 1, code_only, allowlist)
            elif code_only.startswith("from artbot import "):
                rest = code_only[len("from artbot import "):].strip()
                if rest.startswith("(") and ")" not in rest:
                    in_multiline = True
                    _check_allowlist_tokens(ctx, path, idx + 1, rest[1:], allowlist)
                else:
                    _check_allowlist_tokens(ctx, path, idx + 1, rest, allowlist)

def register_api_contract_checks():
    shac.register_check(upstream_artbot_pin_valid)
    shac.register_check(no_private_artbot_apis)
