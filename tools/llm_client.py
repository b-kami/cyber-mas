"""
tools/llm_client.py
-------------------
Central wrapper around the Groq API (LLaMA 3.3-70B).
Every agent calls ask() — nothing else in the project
talks to Groq directly.
"""

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

# ── constants ──────────────────────────────────────────────
MODEL         = "llama-3.3-70b-versatile"
MAX_TOKENS    = 1024
TEMPERATURE   = 0.2   # low = more deterministic, better for security analysis


# ── client (created once, reused across calls) ─────────────
_client: Groq | None = None

def _get_client() -> Groq:
    """Return a shared Groq client, creating it on first call."""
    global _client
    if _client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "GROQ_API_KEY not found. "
                "Add it to your .env file or GitHub Codespaces secrets."
            )
        _client = Groq(api_key=api_key)
    return _client


# ── main function every agent will call ────────────────────
def ask(
    system_prompt: str,
    user_prompt:   str,
    max_tokens:    int = MAX_TOKENS,
    temperature:   float = TEMPERATURE,
) -> str:
    """
    Send a system + user prompt to LLaMA 3.3-70B via Groq.

    Parameters
    ----------
    system_prompt : str
        Defines the LLM's role and output format.
        Example: "You are a cybersecurity analyst. Respond in JSON."
    user_prompt : str
        The actual data to analyse (email text, log lines, scan results).
    max_tokens : int
        Maximum tokens in the response (default 1024).
    temperature : float
        0.0 = fully deterministic, 1.0 = creative. Keep low for security tasks.

    Returns
    -------
    str
        The raw text response from the model.

    Raises
    ------
    EnvironmentError
        If GROQ_API_KEY is missing.
    RuntimeError
        If the Groq API call fails.
    """
    client = _get_client()

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system",  "content": system_prompt},
                {"role": "user",    "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        raise RuntimeError(f"Groq API call failed: {e}") from e


# ── quick self-test (run this file directly to verify setup) ─
if __name__ == "__main__":
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print("\n[bold cyan]Testing Groq connection...[/bold cyan]\n")

    try:
        reply = ask(
            system_prompt="You are a helpful assistant. Be concise.",
            user_prompt="Reply with exactly one sentence confirming you are LLaMA 3.3-70B running on Groq.",
        )
        console.print(Panel(reply, title="[green]LLM response[/green]", border_style="green"))
        console.print("\n[bold green]llm_client.py is working correctly.[/bold green]\n")

    except EnvironmentError as e:
        console.print(f"\n[bold red]Setup error:[/bold red] {e}\n")
    except RuntimeError as e:
        console.print(f"\n[bold red]API error:[/bold red] {e}\n")