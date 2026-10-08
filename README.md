# Understudy

Keep secrets and personal data out of coding-agent API traffic.

> [!WARNING]
> **First version (0.1.0), not yet tested.** It has only been run by its author, on one Mac, with the checks
> described below; it has not been tested by anyone else or on Linux/Windows. Expect rough edges and do not rely on
> it as your only protection for data that must not leave your machine. Bug reports are very welcome.

*An understudy plays the part while the real actor stays offstage.* Your names, emails and keys stay on your
machine; the model talks to convincing stand-ins, and the real values step back in when the answer comes home.

agent-understudy works inside **Claude Code**, **codex** and **opencode**. Before a request leaves your machine,
every API key, password, email, phone number, name and address it finds is swapped for a stand-in. When the
response comes back, stand-ins are restored, so the files your agent writes, the commands it runs and the answer
you read use the real values.

**No daemon.** Each agent session gets its own engine for as long as it runs, on a random localhost port:
opencode's plugin runs it inside opencode, the Claude Code plugin starts it as a child of the session, and
`understudy run codex` starts it for that codex. Sessions share the vault (the same value gets the same stand-in
everywhere) and remembered credentials through files. Models live in one shared sidecar that starts when a
session first needs it and exits after 15 idle minutes.

Personal data gets **realistic stand-ins** the model can still reason about; secrets get opaque tokens:

```
you send       owner = "Maria Santos <maria.santos.dev@gmail.com>", key = ghp_8Kq…
model sees     owner = "Rubie Cremin <rubie.cremin.dev@gmail.com>", key = RDX_SECRET_5cc16aa867
model writes   const rubieCreminId = …  // Signed: Cremin, Rubie   handle 'rcremin'
file on disk   const mariaSantosId = …  // Signed: Santos, Maria   handle 'msantos'
```

Detection is an **ensemble that votes**: gitleaks' 221 secret rules and checksum-validated patterns run in
process, and local models (OpenAI Privacy Filter, a DeBERTa PII tagger, GLiNER-PII, …) run in a Python
sidecar. You choose which models vote and how votes are counted. Nothing is sent anywhere to detect anything.

```
agent ──request──▶ engine (per session) ──redacted──▶ api.anthropic.com / chatgpt.com / any upstream
      ◀─restored──                      ◀──placeholders──
                     │
        gitleaks · patterns (in the engine) · privacy-filter · masker · … (shared sidecar, on demand)
                     │
           vault: placeholder ↔ value (encrypted, local, shared by all sessions)
```

## What it covers

| Host | How | Subscription login |
|---|---|---|
| Claude Code | the plugin: every stored row and the system prompt's session sections are redacted (so local transcripts hold stand-ins too), tool calls get real values, and the screen draws real values. `understudy run claude` also routes the whole request through the engine | ✅ Claude Pro/Max OAuth keeps working |
| codex | `understudy run codex`: `openai_base_url` → that run's engine; HTTP/SSE and the default WebSocket transport, zstd request bodies | ✅ ChatGPT login keeps working |
| opencode | the plugin, in-process (opencode ignores `baseURL` under a ChatGPT login) | ✅ |
| anything OpenAI/Anthropic-compatible | `/u/<name>/…` routes to any upstream you configure (a LiteLLM or other gateway, for example) | — |

Stand-ins are deterministic (seeded by an HMAC of the value under a local key): the same value gives byte-identical
text on every turn, which keeps prompt caching working and satisfies Anthropic's thinking-block signature checks.
Thinking/reasoning blocks are never modified.

## Stand-ins

| Label | Default | What the model sees |
|---|---|---|
| PERSON | surrogate | a realistic name, mapped word by word (given → given, family → family, gender kept when the first name tells), so "Maria" alone, "M. Santos", "Santos, Maria", `maria_santos`, `mariaSantosId` all come back right |
| EMAIL | surrogate | the person's stand-in as the local part; webmail domains kept (gmail.com says nothing about you), company domains → `<word>.example` (RFC 2606) |
| PHONE | surrogate | same format, NANP numbers in the fictional 555-01xx range |
| ADDRESS | surrogate | house number keeps its digit count, street and city replaced, "Lane", commas and state codes kept |
| ACCOUNT / ID / IP | surrogate | same shape; cards keep their issuer digit and pass Luhn; SSNs in the never-issued 9xx range; IPs in TEST-NET-3 |
| SECRET / URL / DATE | token | `RDX_SECRET_5cc16aa867` — a real-looking fake key could be copied somewhere it does damage |

Pick per label in config: `"placeholders": { "PERSON": "numbered" }` gives "Person A", `"token"` gives `RDX_PERSON_…`.
Name structure comes from the taggers' sub-spans (masker/piiranha report given name, surname, street, number,
city, zip); without them names are split by position.

**Restoring explicitly, not hopefully.** Realistic stand-ins that are *not* restored would look like real data in
your files, so restore is deterministic and checked:

- a variant table maps each name's other spellings (`E. Park`, `Park, Elena`, `elena.park`, `elena_park`,
  `ElenaPark`, `elenaPark`, `epark`, `ELENA_PARK`) to the same spelling of the real name, and stand-ins are
  found inside identifiers at camelCase/underscore joints (`getElenaPark`, `elenaParkId`);
- a stand-in word that also occurs as real text in what you send is marked ambiguous and no longer restored on its
  own (it might be a real Elena);
- **before any tool runs**, its restored arguments are checked for stand-in residue (unknown tokens, stand-in
  numbers re-punctuated, stand-in domains); a call that still has some is refused and the model is told to write
  the value verbatim. The Claude Code mod and opencode plugin do this in-process; for codex (and Claude Code
  without the mod) add `hooks/guard.mjs` as a PreToolUse hook;
- `understudy check <files…>` finds stand-ins left in files — put it in a pre-commit hook.

## Install

Needs Node ≥ 24 and [uv](https://docs.astral.sh/uv/) (for the model sidecar). Everything installs inside the repo.

```bash
git clone https://github.com/dajun666/agent-understudy && cd agent-understudy
npm install
bin/understudy setup                  # guided: what to protect, models (pulls them), your names, connecting agents
```

Or step by step:

```bash
(cd sidecar && uv sync)             # torch, transformers, gliner, opf — in sidecar/.venv
bin/understudy models               # list detector models
bin/understudy models pull masker   # ~0.56 GB; add privacy-filter (2.8 GB) etc. as you like
bin/understudy models use masker    # which models vote
npm link                            # puts `understudy` / `agent-understudy` on PATH (the plugins run it)
```

Then use your agents as usual. Nothing has to be started first:

```bash
claude                              # with the plugin installed (below); or: understudy run claude
understudy run codex                # codex with its own engine for this run
opencode                            # with the plugin line in opencode.json (below)
```

`understudy up` is still there for setups that want one long-lived gateway on a fixed port (pointing a LiteLLM
or another tool at it, say); plugins use it when you give them its URL.

Plugins (they run `agent-understudy engine` / `agent-understudy mcp`, so `npm link` first):

```
# Claude Code (in a Claude Code terminal session)
/plugin install agent-understudy --marketplace dajun666/agent-understudy
# codex
codex plugin marketplace add dajun666/agent-understudy && codex plugin add agent-understudy   # then trust its hooks in /hooks
# opencode: opencode.json
{ "plugin": ["file:///abs/path/agent-understudy/hooks/opencode/agent-understudy.ts"] }
# opencode TUI (optional; asks for credentials inside the terminal): tui.json
{ "plugin": ["file:///abs/path/agent-understudy/hooks/opencode/agent-understudy-tui.tsx"] }
```

## Project credentials

API keys your agent's *commands* need but the *model* must never see — a plugin version of
[private project credentials](https://github.com/dajun666/codex-private-project-credentials-demo), for all three hosts.

1. The model calls `secret_request` (name + one line of why). You type the value into a **native masked dialog**
   (macOS; a one-time local page elsewhere) and pick **Remember for this project** or **This session only**.
   The model gets back `Hide(OPENROUTER_API_KEY)`. `secret_list` shows names, never values.
   In Claude Code (terminal or desktop) the mod asks inside Claude Code instead: a pane with the name, the
   model's reason, the project and a field drawn as dots, posted straight to the gateway; `claude -p`, a pane
   the terminal is too narrow to seat, or any failure falls back to the native dialog.
2. Commands read `$AGENT_SECRET_OPENROUTER_API_KEY`. The hook asks the gateway for a one-shot 0600 env file the
   command sources and deletes, so the value never appears in the command text, the transcript or `argv` — and it
   works inside sandboxes that block the network (codex `workspace-write`, Claude Code sandbox mode).
3. Any output containing the value reaches the model as `Hide(NAME)`. References are never turned back into
   values; a tool call that uses `Hide(NAME)` as if it were the value is refused with the right variable to use.
4. Remembered values are AES-256-GCM encrypted per project (`~/.agent-understudy/credentials/<hash of the git root>.json`,
   0600) under a key in the macOS Keychain / Linux Secret Service. No OS credential store → remembering fails
   closed and only session storage is offered. `understudy secret list|set|rm` manages them by hand.

| Host | Ask | Inject into commands | Keep out of local records |
|---|---|---|---|
| Claude Code | in-TUI masked pane (mod), else MCP `secret_request` (declared by the plugin) | mod `tool.call` | mod scrubs `tool_result` **and** Claude Code's own `toolUseResult` — verified: the value appears nowhere in the transcript |
| codex | **in its own TUI**: codex's masked `request_user_input` (the plugin's skill + hooks drive it; choose, Tab, type, Enter) — only when the plugin's hooks are live **and** this session's traffic goes through the gateway (codex re-sends these answers to its guardian model as "verified answers"; the gateway redacts them there). Otherwise the system dialog | plugin PreToolUse hook (`updatedInput`; codex keeps its sandbox and approvals) | PostToolUse replaces the stored tool output and the request_user_input answer; codex core still writes the raw command output (`item_completed`) and the answer (`retained_context`) to the local rollout — closing those needs a codex core change ([openai/codex#47183](https://github.com/openai/codex/issues/47183)) |
| opencode | plugin tools | `shell.env` | requests are redacted; opencode's own session storage keeps raw tool output |

opencode asks **inside its TUI** when `agent-understudy-tui.tsx` is loaded from `tui.json`: a masked field (bullets only,
type or paste) with the same three choices. opencode loads server and TUI plugins from separate files and gives them no
channel to each other, so they meet in `~/.agent-understudy/opencode-asks/` (0700): the tool publishes the request, the
TUI claims it (an exclusive file create, so one TUI wins) and sends the value **straight to the gateway**; only the
outcome goes back to the tool. Nothing in opencode's storage, logs or the tool result holds the value. When no TUI
claims the request within 3 s (`opencode run`, `opencode serve` with a web client) the gateway's native dialog asks
instead; plugin options `tuiAsk: false` / `tuiClaimMs` change that.

Codex runs a plugin's hooks only after you trust them once (`/hooks` in the TUI). The in-TUI prompt uses `request_user_input`, which needs `features.default_mode_request_user_input = true` in `~/.codex/config.toml` outside Plan mode; without it the model falls back to the system dialog.

Scope, same as the reference implementation: this stops *accidental* exposure. A program that receives the
credential can still transform or exfiltrate it, and files commands deliberately write keep the real value.

## Choosing models

| id | size | license | good at | caveat |
|---|---|---|---|---|
| `gitleaks` (always on) | — | MIT rules | 221 provider-specific secret formats, entropy-checked | |
| `patterns` (always on) | — | — | email, cards (Luhn), IBAN (mod-97), US SSN, phone, IPv4, passwords in URLs, OpenRouter keys, US city/state/ZIP | |
| `privacy-filter` | 2.8 GB | Apache-2.0 | the strongest single detector on real agent sessions; 8 labels incl. generic secrets | tags `ls -l` owners, languages and tool attributes as people in tool output — filtered by shape rules |
| `masker` | 0.56 GB | Apache-2.0 | adds names privacy-filter misses | **low precision on tool output**: file sizes, counts and line numbers read as house numbers (dropped: a model-only address needs words) |
| `gliner-pii` | 1.2 GB | NVIDIA Open Model License | zero-shot | slowest, flags git SHAs as secrets; not worth it in the benchmark |
| `piiranha` | 1.1 GB | **CC-BY-NC-ND-4.0** (non-commercial) | — | weakest on real sessions; opt-in only |

**Default: `masker` + `privacy-filter`** (about 3.5 GB RAM), chosen by the benchmark in `bench/`: 650 chunks of
public agent traces, synthetic injections and real sessions, labeled by a large model. On held-out data the pair
reaches 92% recall / 6% leak on synthetic PII and the best F2 on real sessions; GLiNER on top adds ~2 F2 points for
the cost of the slowest model. Lowercase handles are what models miss most — list your own in `knownNames`.

Measured on an M4 / 16 GB: masker ≈ 9k chars/s, privacy-filter ≈ 4k chars/s (CPU; agent-understudy ships a grouped
MoE forward that makes OPF ~7× faster without Triton, with identical spans), gliner-pii ≈ 2.8k chars/s.
A Claude Code session sends ~43k chars on its first request (mostly the system prompt), so the first turn of a
session pays that once; detections are cached by text hash (offsets only, never text) in memory and on disk,
so later turns and later sessions scan only new text. With 16 GB of RAM, keep to one or two models.

## Voting

Overlapping spans from different detectors form one cluster; each detector gets one vote per cluster.

- `weighted` (default): redact when Σ weight × score ≥ the label's threshold. Thresholds are set so **one
  confident model is enough** for PERSON/ADDRESS/PHONE (requiring two models to agree cut name recall on real
  sessions from 45% to 14%), one regex hit is enough for a key. Weights are per detector **per label**.
- Model-only findings are dropped when their shape says tool output, not a person: paths, UUIDs, hashes, versions,
  identifiers, product/common words, languages, system accounts (`root`), file names in `ls -l` listings, and
  addresses without words (sizes, counts, line numbers). Rule-backed findings are never second-guessed.
- Only **confident** findings (a rule, two models, or one model above 0.92) are remembered and redacted everywhere
  afterwards; a doubtful one is redacted where it was found but never spreads.
- A detected name grows to the adjacent capitalized word and to hyphenated surnames (taggers often catch only
  "Okafor" of "Daniel Okafor").
- `any`: any vote redacts. `majority`: more than half of the detectors that cover the label.
- Authoritative detectors (gitleaks, patterns) redact on their own vote and define the exact span.
- Model-only clusters shaped like file paths, UUIDs, hashes or version numbers are kept: prose-trained taggers
  mistake them for IDs, and a redacted path leaves the agent unable to open the file.
- A value redacted once is redacted everywhere afterwards (the vault votes too), including the spellings code
  uses for a known name (`danielOkaforId`, `id-daniel-okafor`, `dokafor`, `Okafor, Daniel`), which go out as the
  same spelling of the stand-in — so history the agent wrote comes back to the model exactly as it saw it.
- Session-only credentials leave a keyed fingerprint (HMAC + length, never the value), so a resumed session's
  stored output is still redacted after the gateway restarted.

All of it is configurable in `~/.agent-understudy/config.json`:

```json
{
  "models": ["masker", "privacy-filter"],
  "names": true,
  "addresses": true,
  "knownNames": ["Jane Roe", "janeroe42"],
  "onDetectorError": "continue",
  "policy": { "mode": "weighted", "thresholds": { "PERSON": 2.0 }, "weights": { "masker": { "PERSON": 1.5 } } },
  "upstreams": { "litellm": "https://llm.example.com" }
}
```

**Names and addresses are optional.** They are the only categories that depend on models, and models catch
names in prose but miss handles, host names and bare surnames in data (about half the names in real sessions).
If you don't need them, turn them off; everything rule-based (keys, emails, phones, cards, IDs, IPs) stays on,
and `knownNames` are still redacted:

```sh
bin/understudy names off        # or on; `bin/understudy names` shows the current setting
bin/understudy addresses off
bin/understudy models use       # optional: with both off, regex only, no model memory
```

## Tools for agents (MCP)

`understudy mcp` serves `secret_request` / `secret_list` (above) and two scanning tools. The scanning tools take
paths, never raw text, because text passed as a tool argument has already been sent to the model.

- `redact_models` — list models (license, size, pulled, loaded, voting), `pull` weights, `use` a set of models.
- `redact_scan` — scan files; per file a verdict (`clean` / `redact` / `review` when detectors disagree below
  threshold) and per finding the label, line, length, placeholder and every detector's vote. Values are never
  returned. Pass `models` / `mode` to compare models on the same file.

`understudy scan <file>` prints the same table in a terminal.

## Limits — read these

- **The model reasons about the stand-in, not the person.** It knows "Rubie" is a first name; it doesn't know
  anything about the real Maria. Secrets stay opaque tokens.
- **Stand-ins are consistent by design** (cache and signatures need it). Research on clinical de-identification
  (BRATsynthetic) shows a value a detector *misses* then stands out among consistent stand-ins; the vault's
  sticky matching (a value redacted once is redacted everywhere) is the mitigation, not a guarantee.
- **Detection is probabilistic.** Regex misses formats it doesn't know; models miss and over-match. Use
  `scan`/`redact_scan` on sensitive files before relying on it, and tune weights.
- **Transformed values are not recognised.** If the agent hex-dumps (`od`), base64-encodes or line-wraps
  (`sed -n l`) a file, the encoded form of a secret is new text no detector knows. Same boundary as any
  redaction proxy: a program holding a value can transform it.
- **Hosts keep their own local copies**, outside what plugins can reach: Claude Code's `toolUseResult` (gateway
  mode), `~/.claude/file-history`, `~/.claude/history.jsonl`; opencode's session database and snapshots; codex's
  rollouts (raw command output, `request_user_input` answers as retained "verified answers", and the guardian
  sub-agent's own rollout). What leaves the machine is redacted; these files are not.
- **Auto/review modes judge credential commands.** Claude Code permissions are evaluated on the command as the
  model wrote it (the mod answers `tool.check` for its env-loading prefix), but auto mode and codex's auto-review
  may still decline a command that sends a credential somewhere; approve it yourself.
- **Only what is launched with it is protected.** A plain `codex` (not `understudy run codex`) talks to OpenAI
  directly. With the codex plugin installed, its SessionStart hook stops such a session's first turn before the
  prompt is sent and says to relaunch with `understudy run codex` (`AGENT_UNDERSTUDY_ALLOW_UNPROTECTED=1` runs it
  anyway). A hook cannot reroute codex, and codex's startup prewarm sends its instructions (AGENTS.md included)
  before any hook runs, so an alias is airtight where the hook is not: `alias codex='understudy run codex'`.
  Claude Code without the plugin and opencode without the plugin line are not protected either. Claude Code's OAuth,
  telemetry and WebFetch domain checks go directly to Anthropic; opencode's session-title request bypasses plugin
  hooks.
- **Local copies.** The Claude Code plugin stores stand-ins in the transcript (its own `toolUseResult` record still
  holds raw tool output locally) and draws real values on screen. `understudy run codex` restores responses before
  codex sees them, so codex's local rollouts hold real values. The opencode plugin redacts the outgoing request only.
- **The PII vault key lives next to the vault** (`~/.agent-understudy/vault.key`, mode 600). Encryption protects copies
  and backups of `vault.jsonl`, not a compromised account. Project credentials use the OS keychain instead.
- **The control API is local and token-gated** (`~/.agent-understudy/api.token`, 0600): anything running as you can
  read that file, so this protects against other users and web pages, not against your own processes.
- While the shared sidecar is starting (its first load takes a few seconds per model), requests wait for it rather
  than going out with fewer votes. If a model fails to load, its votes go missing (regex still runs) unless
  `onDetectorError: "block"`. The Claude Code mod and opencode plugin fail closed by default.

## Develop

```bash
npm test                 # unit + gateway e2e against a fake upstream (no network, no models)
npm run typecheck
claude plugin validate hooks/claude
claude plugin test hooks/claude   # the mod's own tests (hooks/claude/tests)
```

Files: `src/core` (detectors, voting, vault), `src/gateway` (proxy, protocol walkers, stream restore),
`src/mcp`, `sidecar/` (Python models), `hooks/claude`, `hooks/opencode`, `rules/gitleaks.toml` (MIT, gitleaks).

## License

Apache-2.0. `rules/gitleaks.toml` is from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT, see
`rules/GITLEAKS-LICENSE`). Model weights are downloaded from Hugging Face under their own licenses (table above).
