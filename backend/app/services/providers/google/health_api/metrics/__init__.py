"""Unified registry of Google Health API data types — the single source of truth for
what the 24/7 handler emits. Add a metric by appending one ``DataTypeMetric`` to the
relevant family module. Spec types live in ``app.schemas.providers.google``.
"""

from app.config import settings
from app.schemas.providers.google import DataTypeMetric
from app.services.providers.google.health_api.helpers import google_scope_granted
from app.services.providers.google.health_api.metrics.activity import ACTIVITY_METRICS
from app.services.providers.google.health_api.metrics.body import BODY_METRICS
from app.services.providers.google.health_api.metrics.heart import HEART_METRICS
from app.services.providers.google.health_api.metrics.vitals import VITALS_METRICS

# Data types Google gates behind a scope family beyond the activity/health-metrics pair.
# Fetching one without its scope fails that metric with 403 MISSING_OAUTH_SCOPE on every
# sync -- observed for hydration-log, which Google reports as requiring
# ANY_OF[nutrition_readonly] OR ANY_OF[nutrition_writeonly]. Dropping it from the registry
# rather than fetching-and-failing also removes it from GOOGLE_WEBHOOK_DATA_TYPES, which is
# derived from METRICS, so we do not subscribe to pushes we could never read either.
_SCOPE_GATED_DATA_TYPES = {"hydration-log": "nutrition"}

# Deployment allowlist: only ingest the data types this integration actually reads. Separate
# from the scope gate above -- that one drops what Google would refuse, this one drops what we
# would fetch, store, and never look at. Empty means no restriction.
_ALLOWED_DATA_TYPES = {t.strip() for t in settings.google_data_types.split(",") if t.strip()}

_ALL_METRICS = (*ACTIVITY_METRICS, *HEART_METRICS, *BODY_METRICS, *VITALS_METRICS)

METRICS: tuple[DataTypeMetric, ...] = tuple(
    metric
    for metric in _ALL_METRICS
    if (not _ALLOWED_DATA_TYPES or metric.data_type in _ALLOWED_DATA_TYPES)
    and (
        metric.data_type not in _SCOPE_GATED_DATA_TYPES
        or google_scope_granted(_SCOPE_GATED_DATA_TYPES[metric.data_type])
    )
)

__all__ = ["METRICS"]
