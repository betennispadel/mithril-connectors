"""
twitter_scraper.py -- Cookie-based Twitter/X search.

Uses ct0 + auth_token session cookies to hit Twitter internal
GraphQL SearchTimeline endpoint. No API key, no login flow.

Env vars:
    TWITTER_CT0         -- CSRF token cookie
    TWITTER_AUTH_TOKEN  -- Session auth cookie
"""
from __future__ import annotations

import asyncio
import argparse
import json
import os
import sys
import httpx

from query_builder import build_queries

GRAPHQL_SEARCH = "https://x.com/i/api/graphql/UN1i3zUiCWa-6r-Uaho4fw/SearchTimeline"

FEATURES = {
    "rweb_tipjar_consumption_enabled": True,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "verified_phone_label_enabled": False,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "view_counts_everywhere_api_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
}

BEARER = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"


def _headers(ct0, auth_token):
    return {
        "authorization": BEARER,
        "x-csrf-token": ct0,
        "cookie": "ct0=" + ct0 + "; auth_token=" + auth_token,
        "x-twitter-active-user": "yes",
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-client-language": "en",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "content-type": "application/json",
    }


def _parse_tweets(data):
    tweets = []
    try:
        instructions = (
            data.get("data", {})
            .get("search_by_raw_query", {})
            .get("search_timeline", {})
            .get("timeline", {})
            .get("instructions", [])
        )
        for inst in instructions:
            for entry in inst.get("entries", []):
                content = entry.get("content", {})
                item = content.get("itemContent", {})
                if not item:
                    for sub in content.get("items", []):
                        item = sub.get("item", {}).get("itemContent", {})
                        if item.get("tweet_results"):
                            _extract_tweet(item, tweets)
                    continue
                if item.get("tweet_results"):
                    _extract_tweet(item, tweets)
    except Exception as e:
        print("Parse error: " + str(e), file=sys.stderr)
    return tweets


def _extract_tweet(item, tweets):
    result = item.get("tweet_results", {}).get("result", {})
    if result.get("__typename") == "TweetWithVisibilityResults":
        result = result.get("tweet", {})
    legacy = result.get("legacy", {})
    core = result.get("core", {}).get("user_results", {}).get("result", {})
    user_legacy = core.get("legacy", {})
    text = legacy.get("full_text", "")
    if not text:
        return
    tid = legacy.get("id_str", result.get("rest_id", ""))
    username = user_legacy.get("screen_name", "")
    rt = legacy.get("retweet_count", 0)
    likes = legacy.get("favorite_count", 0)
    replies = legacy.get("reply_count", 0)
    engagement = rt + likes + replies
    severity = "info"
    if engagement > 10000 or rt > 1000:
        severity = "high"
    elif engagement > 1000 or rt > 100:
        severity = "medium"
    elif engagement > 100:
        severity = "low"
    tweets.append({
        "id": tid,
        "text": text,
        "author_username": username,
        "author_display": user_legacy.get("name", ""),
        "author_followers": user_legacy.get("followers_count", 0),
        "author_verified": core.get("is_blue_verified", False),
        "created_at": legacy.get("created_at", ""),
        "retweets": rt, "likes": likes, "replies": replies,
        "engagement": engagement, "severity": severity,
        "lang": legacy.get("lang", "en"),
        "url": "https://x.com/" + username + "/status/" + tid if username else "",
        "source_type": "twitter", "source_name": "Twitter/X",
    })


async def search_twitter(target, target_type, ct0, auth_token, max_total=200):
    queries = build_queries(target, target_type)
    all_tweets = {}
    errors = 0
    headers = _headers(ct0, auth_token)

    async with httpx.AsyncClient(timeout=30, http2=True) as client:
        for qinfo in queries:
            if len(all_tweets) >= max_total:
                break
            q = qinfo["query"]
            lang = qinfo["lang"]
            variables = {"rawQuery": q, "count": 20, "querySource": "typed_query", "product": "Latest"}
            params = {"variables": json.dumps(variables), "features": json.dumps(FEATURES)}
            try:
                resp = await client.get(GRAPHQL_SEARCH, headers=headers, params=params)
                if resp.status_code == 429:
                    print("Rate limited, waiting 15s...", file=sys.stderr)
                    await asyncio.sleep(15)
                    continue
                if resp.status_code != 200:
                    errors += 1
                    if errors > 5:
                        break
                    continue
                for tweet in _parse_tweets(resp.json()):
                    tid = tweet["id"]
                    if tid in all_tweets:
                        all_tweets[tid]["found_in_languages"].append(lang)
                        continue
                    tweet["query_lang"] = lang
                    tweet["query_variant"] = qinfo["variant"]
                    tweet["query_terms"] = qinfo["terms"]
                    tweet["found_in_languages"] = [lang]
                    all_tweets[tid] = tweet
            except Exception as e:
                errors += 1
                print("Twitter error (lang=" + lang + "): " + str(e), file=sys.stderr)
                if errors > 5:
                    break
            await asyncio.sleep(1)

    results = list(all_tweets.values())
    results.sort(key=lambda t: t["engagement"], reverse=True)
    return results[:max_total]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--type", required=True, dest="target_type")
    parser.add_argument("--max-results", type=int, default=200)
    args = parser.parse_args()
    ct0 = os.environ.get("TWITTER_CT0", "")
    auth_token = os.environ.get("TWITTER_AUTH_TOKEN", "")
    if not ct0 or not auth_token:
        print("TWITTER_CT0 and TWITTER_AUTH_TOKEN required", file=sys.stderr)
        sys.exit(1)
    results = asyncio.run(search_twitter(args.target, args.target_type, ct0, auth_token, args.max_results))
    json.dump(results, sys.stdout, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
