"""
Base collector — abstract interface that all collectors must implement.

Why an abstract base class?
  Every data source (RSS, API, scraper) is different, but the rest of
  the pipeline doesn't care HOW data was collected. It only cares that
  it receives a list of `RawArticle` objects.

  By defining this contract, we can add new collectors (De.Fi API,
  future scrapers, etc.) without changing the pipeline code.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from app.models.schemas import RawArticle, SourceConfig

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """
    Abstract base class for all data source collectors.

    Every collector must:
      1. Accept a SourceConfig in __init__
      2. Implement collect() → list of RawArticle
      3. Handle its own errors gracefully (return [] on failure, don't crash)
    """

    def __init__(self, source: SourceConfig):
        self.source = source
        self.logger = logging.getLogger(f"collector.{source.name}")

    @abstractmethod
    async def collect(self) -> list[RawArticle]:
        """
        Fetch new items from this source.

        Returns:
            List of RawArticle objects. Empty list if the source is
            down or returned nothing new.

        This method must NOT raise exceptions — catch everything
        internally and log errors. One broken source must never
        crash the entire pipeline.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} source={self.source.name!r}>"
