from .feodo import FeodoFeed
from .threatfox import ThreatFoxFeed
from .urlhaus import URLhausFeed

# Registry of active feeds. Add a new feed by dropping it in here.
FEEDS = [URLhausFeed(), ThreatFoxFeed(), FeodoFeed()]

__all__ = ["FEEDS", "URLhausFeed", "ThreatFoxFeed", "FeodoFeed"]
