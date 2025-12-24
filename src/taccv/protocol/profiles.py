from __future__ import annotations
from .constants import PROFILE_RANKS, MIN_PROFILE

def profile_allowed(profile: str) -> bool:
    if profile not in PROFILE_RANKS:
        return False
    return PROFILE_RANKS[profile] >= PROFILE_RANKS[MIN_PROFILE]

def negotiate_profile(my_profiles: list[str], peer_profiles: list[str]) -> str:
    for profile in sorted(my_profiles, key=lambda p: PROFILE_RANKS.get(p, 0), reverse=True):
        if profile in peer_profiles and profile_allowed(profile):
            return profile
    raise ValueError("No mutually supported profile")
