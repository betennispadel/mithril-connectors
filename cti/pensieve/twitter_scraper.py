"""
twitter_scraper.py — Session-based Twitter/X search via twscrape.

No official API key needed. Uses account pool for session auth.
Multilingual queries via query_builder.

Usage:
    python3 twitter_scraper.py         --target "example.com"         --type DOMAIN         --accounts-file /data/twitter_accounts.json         --max-results 50

Accounts file format:
    [{"username": "...", "password": "...", "email": "...", "email_password": "..."}]

Output: JSON array of tweet objects to stdout.
"""
from __future__ import annotations

import asyncio
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

# twscrape must be installed in the container (Dockerfile)
try:
    from twscrape import API, gather
    from twscrape.logger import set_log_level
    HAS_TWSCRAPE = True
except ImportError:
    HAS_TWSCRAPE = False

from query_builder import build_queries, LANGUAGES


DB_PATH = os.environ.get("TWSCRAPE_DB", "/data/twscrape.db")
ACCOUNTS_FILE = os.environ.get("TWITTER_ACCOUNTS_FILE", "/data/twitter_accounts.json")


async def ensure_accounts(api: API, accounts_file: str) -> int:
    """Add accounts from JSON file if not already in pool. Returns count."""
    if not Path(accounts_file).exists():
        # Try env var fallback: TWITTER_USERNAME, TWITTER_PASSWORD, TWITTER_EMAIL, TWITTER_EMAIL_PASSWORD
        u = os.environ.get("TWITTER_USERNAME", "")
        p = os.environ.get("TWITTER_PASSWORD", "")
        e = os.environ.get("TWITTER_EMAIL", "")
        ep = os.environ.get("TWITTER_EMAIL_PASSWORD", "")
        if u and p:
            await api.pool.add_account(u, p, e, ep)
            await api.pool.login_all()
            return 1
        return 0

    accounts = json.loads(Path(accounts_file).read_text())
    count = 0
    for acc in accounts:
        try:
            await api.pool.add_account(
                acc["username"],
                acc["password"],
                acc.get("email", ""),
                acc.get("email_password", ""),
            )
            count += 1
        except Exception:
            pass  # already exists or bad creds

    if count > 0:
        await api.pool.login_all()
    return count


async def search_twitter(
    target: str,
    target_type: str,
    max_results_per_query: int = 30,
    max_total: int = 200,
    accounts_file: Optional[str] = None,
) -> list[dict]:
    """
    Search Twitter with multilingual queries.
    Returns list of tweet dicts with metadata.
    """
    if not HAS_TWSCRAPE:
        print("twscrape not installed", file=sys.stderr)
        return []

    set_log_level("WARNING")
    api = API(DB_PATH)

    # Ensure accounts are loaded
    n = await ensure_accounts(api, accounts_file or ACCOUNTS_FILE)
    if n == 0:
        # Check if pool already has accounts
        stats = await api.pool.stats()
        if stats.get("total", 0) == 0:
            print("No Twitter accounts available", file=sys.stderr)
            return []

    queries = build_queries(target, target_type)
    all_tweets = {}  # tweet_id → tweet dict (dedup)
    errors = 0

    for qinfo in queries:
        if len(all_tweets) >= max_total:
            break

        q = qinfo["query"]
        lang = qinfo["lang"]
        variant = qinfo["variant"]

        try:
            tweets = await gather(api.search(q, limit=max_results_per_query))
            for tweet in tweets:
                tid = str(tweet.id)
                if tid in all_tweets:
                    # Already seen, just add the query language that found it
                    all_tweets[tid]["found_in_languages"].add(lang)
                    continue

                # Classify severity by engagement
                rt = tweet.retweetCount or 0
                likes = tweet.likeCount or 0
                replies = tweet.replyCount or 0
                engagement = rt + likes + replies

                severity = "info"
                if engagement > 10000 or rt > 1000:
                    severity = "high"
                elif engagement > 1000 or rt > 100:
                    severity = "medium"
                elif engagement > 100:
                    severity = "low"

                all_tweets[tid] = {
                    "id": tid,
                    "text": tweet.rawContent,
                    "author_username": tweet.user.username if tweet.user else "",
                    "author_display": tweet.user.displayname if tweet.user else "",
                    "author_followers": tweet.user.followersCount if tweet.user else 0,
                    "author_verified": tweet.user.verified if tweet.user else False,
                    "created_at": tweet.date.isoformat() if tweet.date else "",
                    "retweets": rt,
                    "likes": likes,
                    "replies": replies,
                    "engagement": engagement,
                    "severity": severity,
                    "lang": tweet.lang or lang,
                    "url": f"https://x.com/{tweet.user.username}/status/{tid}" if tweet.user else "",
                    "query_lang": lang,
                    "query_variant": variant,
                    "query_terms": qinfo["terms"],
                    "found_in_languages": {lang},
                    # VoidAccess-compatible page format
                    "source_type": "twitter",
                    "source_name": "Twitter/X",
                }

        except Exception as e:
            errors += 1
            print(f"Twitter search error (lang={lang}): {e}", file=sys.stderr)
            if errors > 5:
                break  # Too many errors, probably rate limited
            await asyncio.sleep(2)

    # Convert sets to lists for JSON
    results = list(all_tweets.values())
    for r in results:
        r["found_in_languages"] = list(r["found_in_languages"])

    # Sort by engagement
    results.sort(key=lambda t: t["engagement"], reverse=True)
    return results[:max_total]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--type", required=True, dest="target_type")
    parser.add_argument("--max-results", type=int, default=200)
    parser.add_argument("--max-per-query", type=int, default=30)
    parser.add_argument("--accounts-file", default=ACCOUNTS_FILE)
    args = parser.parse_args()

    results = asyncio.run(search_twitter(
        target=args.target,
        target_type=args.target_type,
        max_results_per_query=args.max_per_query,
        max_total=args.max_results,
        accounts_file=args.accounts_file,
    ))

    json.dump(results, sys.stdout, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
