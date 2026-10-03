"""
Live data retrieval client for ProvGuard-MAS LangGraph simulation.
Fetches real-time content from Wikipedia REST API and arbitrary web URLs.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("provguard.simulation.live_retrieval")


class LiveDataFetcher:
    """
    Retrieves live external data for the multi-agent system.
    Supports Wikipedia API and direct HTTP URL content retrieval.
    """

    DEFAULT_USER_AGENT = "ProvGuard-MAS-Researcher/1.0 (academic research testbed; security-agent@provguard.local)"

    @classmethod
    def fetch_wikipedia_summary(cls, query: str, timeout: float = 6.0) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Fetches live real-time article summary from Wikipedia REST API.
        Returns: (success, extracted_text, metadata)
        """
        # Clean query: strip 'research:' or 'search:' prefixes
        clean_topic = re.sub(r"^(?:research|search):\s*", "", query, flags=re.IGNORECASE).strip()
        if not clean_topic:
            clean_topic = "Artificial intelligence"

        encoded_title = urllib.parse.quote(clean_topic.replace(" ", "_"))
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{encoded_title}"

        req = urllib.request.Request(
            url,
            headers={"User-Agent": cls.DEFAULT_USER_AGENT, "Accept": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    extract = data.get("extract", "")
                    title = data.get("title", clean_topic)
                    meta = {
                        "source": "Wikipedia API (Live)",
                        "url": data.get("content_urls", {}).get("desktop", {}).get("page", url),
                        "title": title,
                        "timestamp": data.get("timestamp"),
                    }
                    if extract:
                        return True, f"[Live Wikipedia: {title}] {extract}", meta
        except Exception as e:
            logger.warning(f"Live Wikipedia fetch for '{clean_topic}' encountered: {e}")

        # Fallback to general search API
        search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={urllib.parse.quote(clean_topic)}&format=json"
        try:
            req_search = urllib.request.Request(search_url, headers={"User-Agent": cls.DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req_search, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                search_results = data.get("query", {}).get("search", [])
                if search_results:
                    first = search_results[0]
                    clean_snippet = re.sub(r"<[^>]+>", "", first.get("snippet", ""))
                    return True, f"[Live Wikipedia: {first.get('title')}] {clean_snippet}", {
                        "source": "Wikipedia Search API (Live)",
                        "title": first.get("title"),
                    }
        except Exception as e:
            logger.warning(f"Wikipedia fallback search failed: {e}")

        return False, f"Could not retrieve live Wikipedia content for '{clean_topic}'. Using live simulated fallback.", {
            "source": "Fallback Offline Buffer",
        }

    @classmethod
    def fetch_url_content(cls, url: str, timeout: float = 6.0) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Fetches live web page content from an arbitrary HTTP/HTTPS URL and strips HTML.
        """
        req = urllib.request.Request(
            url,
            headers={"User-Agent": cls.DEFAULT_USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read(65536)  # Read up to 64KB
                html_text = raw_bytes.decode("utf-8", errors="ignore")
                
                # Simple HTML tag removal
                text = re.sub(r"<script[\s\S]*?</script>", "", html_text, flags=re.IGNORECASE)
                text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
                text = re.sub(r"<[^>]+>", " ", text)
                clean_text = " ".join(text.split())[:1200]
                
                return True, clean_text, {
                    "source": "Live Web Page",
                    "url": url,
                    "length": len(clean_text),
                }
        except Exception as e:
            logger.warning(f"Failed to fetch live URL '{url}': {e}")
            return False, f"Error fetching live URL {url}: {e}", {"error": str(e)}

    @classmethod
    def fetch_live_data(
        cls,
        query_or_url: str,
        adversarial_injection: Optional[str] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Universal live fetcher for simulation:
        1. If input is a URL (starts with http:// or https://), fetch webpage.
        2. Otherwise, query Wikipedia API.
        3. If adversarial_injection is provided, inject it into the live content to test defense in real time.
        """
        if query_or_url.startswith("http://") or query_or_url.startswith("https://"):
            success, content, meta = cls.fetch_url_content(query_or_url)
        else:
            success, content, meta = cls.fetch_wikipedia_summary(query_or_url)

        # Inject adversarial payload if requested (simulates live external page poisoning / indirect injection)
        if adversarial_injection:
            injected_content = f"{content}\n\n<!-- Injected External Payload: {adversarial_injection} -->"
            meta["is_tampered_with_injection"] = True
            meta["injected_payload"] = adversarial_injection
            return injected_content, meta

        meta["is_tampered_with_injection"] = False
        return content, meta
