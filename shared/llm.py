"""Model configuration and multi-provider routing for every agent system.

One place decides how the project talks to LLMs, so the six systems share a
single provider-fallback policy instead of each calling a provider SDK
directly. Phase 2 added the routing layer (`llm_chain`, `adk_model`,
`crew_llm`) on top of the Phase 1 config/retry helpers.

Also the one place that loads `.env`. Each system process calls
`load_project_env()` at startup; nothing else should touch dotenv.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, TypeVar

logger = logging.getLogger(__name__)

# --- Phase 6.2: best-effort "which model actually served this call" capture --------------------------
#
# shared/reasoning.py's start_call()/resolve() wants to tag a reasoning entry with the model that
# answered, without the model-building code (adk_model/crew_llm, built once per agent, not per call)
# needing to know about any of it. A contextvar does the job: the caller sets it right before the
# await/asyncio.to_thread() that triggers the real call, the provider-served logger below appends to it
# from inside litellm's success callback (which fires within that call's dynamic scope), and the caller
# reads it back right after. asyncio.to_thread() copies the current context into its worker thread, so
# this also works for the CrewAI systems, which all go through asyncio.to_thread.
#
# Best-effort, not guaranteed: if the callback has not fired yet when the caller reads it (litellm/CrewAI
# can dispatch it slightly after the call returns -- see scripts/test_llm_routing.py's note on this), the
# capture is just empty and the caller shows no served_by tag. Never raises, never blocks.
_served_sink: "contextvars.ContextVar[Optional[list]]" = contextvars.ContextVar("llm_served_sink", default=None)


def served_capture_start():
    """Begin capturing the model tag for the next call(s) on this task/thread context. Returns a token
    for served_capture_stop(). Pair with served_capture_read() after the call returns."""
    return _served_sink.set([])


def served_capture_read() -> Optional[str]:
    """The most recent model tag captured since served_capture_start(), or None if none has arrived yet."""
    box = _served_sink.get()
    return box[-1] if box else None


def served_capture_stop(token) -> None:
    try:
        _served_sink.reset(token)
    except Exception:  # noqa: BLE001 - this is demo instrumentation; it must never break a real call
        pass

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"

# Verified reachable on 2026-10-03 with this project's key.
#
# `gemini-2.0-flash` -- what the Phase 0 scaffold referenced -- is retired and
# now 404s. `gemini-3.8-flash` exists but returned 503 "high demand" on every
# attempt, so it is not a safe default for an unattended pipeline. 2.5-flash is
# GA, fast, and answered immediately.
DEFAULT_MODEL = "gemini-2.5-flash"

# Used where a step benefits from more capable reasoning than the default.
# Same family, so behaviour stays comparable.
DEFAULT_REASONING_MODEL = "gemini-2.5-flash"

# A deliberately *different* model family for Detection's noise filter.
#
# The Gemini free tier meters requests per model per minute (~5 RPM), and one
# incident fires several calls across Detection and Threat Assessment. Putting
# the noise filter on its own model means its calls draw from a separate quota
# bucket than Threat Assessment's, so a single incident does not exhaust one
# model's per-minute budget. gemini-2.5-flash-lite is closed to new keys now;
# 3.5-flash-lite is its live replacement.
DEFAULT_FILTER_MODEL = "gemini-3.5-flash-lite"

_ENV_LOADED = False


def load_project_env(*, required_keys: tuple[str, ...] = ()) -> None:
    """Load `.env` from the project root, then assert the keys we need exist.

    Idempotent. Existing environment variables win over the file, so a shell
    override or a CI secret is not clobbered by a stale `.env`.
    """
    global _ENV_LOADED
    if not _ENV_LOADED:
        try:
            from dotenv import load_dotenv

            if ENV_FILE.exists():
                load_dotenv(ENV_FILE, override=False)
                logger.debug("loaded env from %s", ENV_FILE)
            else:
                logger.warning("no .env at %s -- relying on the ambient environment", ENV_FILE)
        except ImportError:
            logger.warning("python-dotenv not installed -- relying on the ambient environment")
        _ENV_LOADED = True

    missing = [k for k in required_keys if not os.environ.get(k)]
    if missing:
        raise RuntimeError(
            f"missing required environment variable(s): {', '.join(missing)}. "
            f"Add them to {ENV_FILE} (see .env.example)."
        )


def google_api_key() -> Optional[str]:
    return os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")


def require_google_api_key() -> str:
    """Fail loudly and early rather than at the first model call.

    Phase 1's agents are reasoning agents; without a key there is nothing to
    degrade to, so a process that cannot reason should not start and pretend
    otherwise.
    """
    load_project_env()
    key = google_api_key()
    if not key:
        raise RuntimeError(
            "GOOGLE_API_KEY (or GEMINI_API_KEY) is not set. The Detection and "
            "Threat Assessment systems are LLM-backed and cannot run without "
            f"it. Add it to {ENV_FILE} -- see .env.example."
        )
    return key


@lru_cache(maxsize=1)
def model_name() -> str:
    """The model every agent uses. Override with GEMINI_MODEL."""
    load_project_env()
    return os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)


@lru_cache(maxsize=1)
def reasoning_model_name() -> str:
    """Model for the heavier reasoning steps. Override with GEMINI_REASONING_MODEL."""
    load_project_env()
    return os.environ.get("GEMINI_REASONING_MODEL", DEFAULT_REASONING_MODEL)


@lru_cache(maxsize=1)
def filter_model_name() -> str:
    """Model for Detection's noise filter. Separate bucket from Threat
    Assessment on purpose -- see DEFAULT_FILTER_MODEL. Override with
    GEMINI_FILTER_MODEL."""
    load_project_env()
    return os.environ.get("GEMINI_FILTER_MODEL", DEFAULT_FILTER_MODEL)


T = TypeVar("T")

# How long the free-tier quota window is. A 429 says "retry in Ns"; we honor
# that but cap it so a wedged quota cannot block a process indefinitely.
_MAX_BACKOFF_S = float(os.environ.get("GEMINI_MAX_BACKOFF", "65"))
_RETRY_ATTEMPTS = int(os.environ.get("GEMINI_RETRY_ATTEMPTS", "4"))


def _is_rate_limit(exc: BaseException) -> bool:
    text = str(exc)
    return "RESOURCE_EXHAUSTED" in text or "429" in text


def _suggested_delay(exc: BaseException) -> Optional[float]:
    """Pull the server's suggested retry delay out of a 429 message, if present."""
    m = re.search(r"retry in ([0-9.]+)s", str(exc)) or re.search(r"retryDelay['\"]?: ?['\"]?([0-9.]+)s", str(exc))
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


async def run_with_rate_limit_retry(
    factory: Callable[[], Awaitable[T]],
    *,
    label: str = "llm call",
    attempts: int = _RETRY_ATTEMPTS,
) -> T:
    """Await `factory()`, retrying on Gemini rate-limit (429) errors.

    The free tier allows very few requests per minute, and a multi-agent
    pipeline bunches calls, so transient 429s are expected rather than
    exceptional. Honors the server's suggested delay (capped), backs off
    otherwise, and re-raises anything that is not a rate-limit error at once.
    `factory` must build a fresh awaitable each call, since an awaitable cannot
    be retried once consumed.
    """
    last: Optional[BaseException] = None
    for attempt in range(1, attempts + 1):
        try:
            return await factory()
        except BaseException as exc:  # noqa: BLE001 - re-raised below unless rate limit
            if not _is_rate_limit(exc):
                raise
            last = exc
            if attempt == attempts:
                break
            delay = _suggested_delay(exc)
            delay = min(delay if delay is not None else 2 ** attempt, _MAX_BACKOFF_S)
            logger.warning(
                "%s hit the Gemini rate limit (attempt %d/%d); retrying in %.0fs",
                label, attempt, attempts, delay,
            )
            await asyncio.sleep(delay)
    assert last is not None
    raise last


# ==========================================================================
# Multi-provider LLM routing (Phase 2, Task 1)
# ==========================================================================
#
# Every agent asks this module for a model object rather than naming a provider
# itself. The object is pre-configured with a per-role fallback chain, so no
# single provider's free-tier limit can stall the pipeline the way Gemini's did
# in Phase 1. LiteLLM does the fallback natively: given a `fallbacks=[...]`
# kwarg it retries the *original* prompt on the next model on an upfront
# rejection (429 / quota / auth) -- which is exactly the Phase 1 failure mode.
# Both ADK's LiteLlm wrapper and CrewAI's LLM forward that kwarg to litellm.

ROLE_REASONING = "reasoning"
ROLE_MECHANICAL = "mechanical"

# Default chains in litellm model-string form ("provider/model"). Ordered by
# preference; the first reachable one is primary, the rest are fallbacks.
# These encode the Phase 2 brief's intent; the actual working order is set in
# `.env` (LLM_CHAIN_REASONING / LLM_CHAIN_MECHANICAL), because which providers
# have credentials/quota is a deployment fact, not a code constant.
_DEFAULT_CHAINS: Dict[str, List[str]] = {
    # Reasoning-heavy: severity classification, threat correlation, (later)
    # root-cause analysis.
    ROLE_REASONING: [
        "gemini/gemini-2.5-flash",
        "cerebras/llama-3.3-70b",
        "openrouter/meta-llama/llama-3.3-70b-instruct:free",
    ],
    # Mechanical/simple: noise-filter verdicts, status lookups. Local first so
    # it costs no hosted quota; Gemini only as a fallback.
    ROLE_MECHANICAL: [
        "ollama/llama3.1:8b",
        "gemini/gemini-flash-lite-latest",
    ],
}

_ENV_CHAIN_VARS = {
    ROLE_REASONING: "LLM_CHAIN_REASONING",
    ROLE_MECHANICAL: "LLM_CHAIN_MECHANICAL",
}


def _provider_of(model_string: str) -> str:
    return model_string.split("/", 1)[0] if "/" in model_string else "gemini"


@lru_cache(maxsize=1)
def _ollama_reachable() -> bool:
    """Whether a local Ollama server is answering.

    The mechanical chain lists Ollama first, but it is an optional local
    dependency. If nothing is listening we prune it rather than waste a
    fallback hop (and a few seconds of connection timeout) on every call.
    """
    base = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
    try:
        import urllib.request

        with urllib.request.urlopen(f"{base}/api/tags", timeout=1.5) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


def _has_credentials(provider: str) -> bool:
    """Whether a provider is usable right now, so keyless ones are pruned."""
    if provider in ("gemini", "google", "vertex_ai"):
        return bool(google_api_key())
    if provider == "ollama":
        return _ollama_reachable()
    env_key = {
        "cerebras": "CEREBRAS_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "groq": "GROQ_API_KEY",
    }.get(provider)
    if env_key is None:
        # Unknown provider: assume the operator configured it deliberately.
        return True
    return bool(os.environ.get(env_key))


def _raw_chain(role: str) -> List[str]:
    load_project_env()
    env_var = _ENV_CHAIN_VARS.get(role)
    raw = os.environ.get(env_var) if env_var else None
    if raw:
        return [m.strip() for m in raw.split(",") if m.strip()]
    return list(_DEFAULT_CHAINS.get(role, _DEFAULT_CHAINS[ROLE_REASONING]))


@lru_cache(maxsize=8)
def llm_chain(role: str) -> tuple:
    """The resolved, credential-pruned fallback chain for a role.

    Returns a tuple (hashable, cacheable) of litellm model strings, primary
    first. Models whose provider has no usable credentials are dropped so a
    call never wastes a hop on a provider that cannot possibly answer. If
    pruning removes everything, falls back to the raw chain and lets the call
    fail loudly rather than silently doing nothing.
    """
    raw = _raw_chain(role)
    pruned = [m for m in raw if _has_credentials(_provider_of(m))]
    dropped = [m for m in raw if m not in pruned]
    if dropped:
        logger.info(
            "llm_chain[%s]: pruned unavailable providers %s; using %s",
            role, dropped, pruned or "(none left)",
        )
    if not pruned:
        logger.warning(
            "llm_chain[%s]: no configured provider has credentials; "
            "keeping raw chain %s so the failure is visible", role, raw,
        )
        return tuple(raw)
    return tuple(pruned)


# --- provider-served logging ---------------------------------------------


def _served_model(kwargs, response_obj) -> str:
    return getattr(response_obj, "model", None) or kwargs.get("model", "?")


def _agent_of(kwargs) -> str:
    meta = (kwargs.get("litellm_params", {}) or {}).get("metadata", {}) or {}
    return meta.get("agent_name") or meta.get("agent_role") or "?"


def _make_provider_logger():
    """Build the litellm callback that records which model served each call.

    Subclasses litellm's CustomLogger (litellm only dispatches to instances of
    it, or to plain callables), so the served-by line actually fires -- which
    is what makes fallback visible in the audit trail instead of silent.
    Built lazily so importing this module needs no litellm.
    """
    from litellm.integrations.custom_logger import CustomLogger

    class _ProviderLogger(CustomLogger):
        def log_success_event(self, kwargs, response_obj, start_time, end_time):
            model = _served_model(kwargs, response_obj)
            logger.info("[llm] agent=%s served_by=%s", _agent_of(kwargs), model)
            box = _served_sink.get()
            if box is not None:
                box.append(model)

        async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
            model = _served_model(kwargs, response_obj)
            logger.info("[llm] agent=%s served_by=%s", _agent_of(kwargs), model)
            box = _served_sink.get()
            if box is not None:
                box.append(model)

        def log_failure_event(self, kwargs, response_obj, start_time, end_time):
            logger.warning("[llm] agent=%s call to %s failed (fallback if any): %s",
                           _agent_of(kwargs), kwargs.get("model", "?"), str(response_obj)[:140])

        async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
            logger.warning("[llm] agent=%s call to %s failed (fallback if any): %s",
                           _agent_of(kwargs), kwargs.get("model", "?"), str(response_obj)[:140])

    return _ProviderLogger()


_PROVIDER_LOGGER = None  # the single logger instance, built once


def install_llm_logging() -> None:
    """Ensure the provider-served logger is registered with litellm.

    Idempotent and safe to call repeatedly -- which matters because CrewAI
    rewrites `litellm.success_callback` when it constructs an LLM, so this is
    re-asserted after each crew_llm() build. The logger is added to all three
    litellm hook lists: `callbacks` (the path ADK's wrapper triggers) and
    `success_callback`/`failure_callback` (the lists CrewAI manages).
    """
    global _PROVIDER_LOGGER
    try:
        import litellm
    except ImportError:
        logger.warning("litellm not installed; provider logging unavailable")
        return

    if _PROVIDER_LOGGER is None:
        _PROVIDER_LOGGER = _make_provider_logger()
        litellm.suppress_debug_info = True

    for list_name in ("callbacks", "success_callback", "failure_callback"):
        current = list(getattr(litellm, list_name, []) or [])
        if _PROVIDER_LOGGER not in current:
            current.append(_PROVIDER_LOGGER)
            setattr(litellm, list_name, current)


# --- framework model factories -------------------------------------------


def _metadata(role: str, agent_name: str) -> Dict[str, Any]:
    return {"agent_role": role, "agent_name": agent_name}


def adk_model(role: str, *, agent_name: str):
    """An ADK model object for `role`, wired with the role's fallback chain.

    Returns a `google.adk.models.lite_llm.LiteLlm` whose primary is the chain
    head and whose `fallbacks` are the rest. Imported lazily so this module is
    importable in venvs without ADK installed.
    """
    from google.adk.models.lite_llm import LiteLlm

    install_llm_logging()
    chain = list(llm_chain(role))
    primary, fallbacks = chain[0], chain[1:]
    logger.info("adk_model[%s] agent=%s primary=%s fallbacks=%s", role, agent_name, primary, fallbacks)
    return LiteLlm(
        model=primary,
        fallbacks=fallbacks,
        metadata=_metadata(role, agent_name),
        drop_params=True,  # providers differ on which params they accept
    )


def crew_llm(role: str, *, agent_name: str, **kwargs):
    """A CrewAI LLM for `role`, wired with the role's fallback chain.

    Returns a `crewai.LLM`. Imported lazily so this module is importable in
    venvs without CrewAI installed.
    """
    from crewai import LLM

    chain = list(llm_chain(role))
    primary, fallbacks = chain[0], chain[1:]
    # CrewAI 1.x routes a bare "gemini/..." model to its *native* google-genai
    # provider, which bypasses LiteLLM entirely -- losing our fallback chain and
    # provider logging (and it isn't even installed). The "litellm/" prefix
    # forces CrewAI's LiteLLM route instead. Only the primary goes through
    # CrewAI's resolver; the fallbacks are consumed by LiteLLM directly, so they
    # stay as plain provider strings.
    crew_primary = primary if primary.startswith("litellm/") else f"litellm/{primary}"
    logger.info("crew_llm[%s] agent=%s primary=%s fallbacks=%s", role, agent_name, crew_primary, fallbacks)
    model = LLM(
        model=crew_primary,
        fallbacks=fallbacks,
        metadata=_metadata(role, agent_name),
        **kwargs,
    )
    # CrewAI rewrites litellm.success_callback while building the LLM, so
    # register our logger afterwards, not before.
    install_llm_logging()
    return model


def finish_reason_is_truncation(response_obj: Any) -> bool:
    """Whether a completion stopped because it ran out of room, not naturally."""
    try:
        reason = response_obj.choices[0].finish_reason
    except (AttributeError, IndexError, KeyError):
        return False
    return reason in ("length", "max_tokens")


def _content_of(response_obj: Any) -> str:
    try:
        return response_obj.choices[0].message.content or ""
    except (AttributeError, IndexError, KeyError):
        return ""


# ==========================================================================
# Partial-generation-cutoff handling (Phase 3, Task 3) -- RCA only.
# ==========================================================================
#
# LiteLLM's fallbacks already cover *upfront* rejection (429/quota/auth before
# any tokens). This covers the other case: a provider that returns a partial
# answer and then stops mid-generation (finish_reason == length). We iterate
# the role's chain ourselves so we control what happens between models:
#   * natural stop  -> done,
#   * mid-cutoff    -> keep the partial text and ask the NEXT model to continue
#                      it ("continuation" mode),
#   * upfront error -> move to the next model with the original prompt (same as
#                      the Phase 2 fallback behaviour).
#
# Scoped to the Root Cause Analysis agent -- the project's only long-form,
# open-ended reasoner. Do NOT wire this into the short bounded-decision agents.


class RcaGeneration(Dict[str, Any]):
    """Just a dict; typed alias for readability of the return value."""


def generate_with_continuation(
    role: str,
    *,
    system_prompt: str,
    user_prompt: str,
    agent_name: str = "root_cause_analysis",
    max_tokens_per_round: int = 900,
    max_rounds: int = 4,
    prefer_continuation: bool = True,
) -> Dict[str, Any]:
    """Generate long-form text across the role's chain, stitching partial cutoffs.

    Returns {text, rounds, providers, continued, mode, finished}. Synchronous;
    call it from a worker thread in an async server.

    `prefer_continuation=False` (or falling back to it automatically if a seam
    looks broken) discards the partial and retries the full prompt on the next
    model instead -- the simpler behaviour the brief allows.
    """
    install_llm_logging()
    import litellm

    chain = list(llm_chain(role))
    base_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    accumulated = ""
    providers: List[str] = []
    mode = "single"
    finished = False

    for rnd in range(max_rounds):
        model = chain[min(rnd, len(chain) - 1)]
        if accumulated and prefer_continuation:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": accumulated},
                {"role": "user", "content":
                    "Your previous response was cut off mid-sentence. Continue it "
                    "naturally from exactly where it stopped. Do not repeat anything "
                    "you already wrote and do not restart; just carry on to a clean finish."},
            ]
        else:
            messages = base_messages

        try:
            resp = litellm.completion(
                model=model, messages=messages,
                max_tokens=max_tokens_per_round,
                metadata=_metadata(role, agent_name),
            )
        except Exception as exc:  # noqa: BLE001 - upfront rejection -> next model, original prompt
            logger.warning("rca round %d on %s failed upfront (%s); next model", rnd, model, str(exc)[:100])
            if not prefer_continuation:
                accumulated = ""  # ensure retry uses base prompt
            continue

        part = _content_of(resp)
        providers.append(getattr(resp, "model", model))

        if not finish_reason_is_truncation(resp):
            accumulated = (accumulated + part) if (accumulated and prefer_continuation) else part
            finished = True
            if rnd > 0:
                mode = "continuation" if prefer_continuation else "retry"
            break

        # truncated mid-generation
        logger.info("rca round %d on %s truncated; %s", rnd, model,
                    "continuing on next model" if prefer_continuation else "retrying on next model")
        if prefer_continuation:
            accumulated = (accumulated + part) if accumulated else part
            mode = "continuation"
        else:
            accumulated = ""
            mode = "retry"

    return {
        "text": accumulated.strip(),
        "rounds": len(providers),
        "providers": providers,
        "continued": mode == "continuation" and len(providers) > 1,
        "mode": mode,
        "finished": finished,
    }
