import stix2
import bisect
from pydantic import BaseModel
from functools import cache


# TODO: Improve logic, avoid all recalculations (unless cache fixes this?)
class SightingsCollector:
    """
    Helper module to reduce the number of sightings to one instance per SDO

    When a sighting is added using add(), the metadata passed to the function
    is added to an object, Meta. Any subsequent calls for the same sighter_id
    updates first_seen, last_seen and count accordingly.

    Additional helper functions extract alerts by rule ID or sighter.
    """

    class Meta(BaseModel):
        observable_id: str
        sighter_name: str
        first_seen: str  # prefer over datetime, because it will be used as str later
        last_seen: str  # prefer over datetime, because it will be used as str later
        count: int
        alerts: dict[str, list[dict]]
        max_rule_level: int = 0

    def __init__(self, *, observable_id: str):
        self._sightings: dict[str, SightingsCollector.Meta] = {}
        # This module will only be used for one SCO at a time:
        self._observable_id = observable_id
        self._latest = ""

    @cache
    def _alerts_timestamps_sorted(self, rule_id: str):
        return [
            alert["_source"]["@timestamp"]
            for sighting in self._sightings.values()
            for alert in sighting.alerts.get(rule_id, [])
        ]

    def add(self, *, timestamp: str, sighter: stix2.Identity, alert: dict):
        """
        Add or update metadata for sightings of an observable in sighter_id
        """
        rule_id = alert["_source"]["rule"]["id"]
        if sighter.id in self._sightings:
            self._sightings[sighter.id].first_seen = min(
                self._sightings[sighter.id].first_seen, timestamp
            )
            self._sightings[sighter.id].last_seen = max(
                self._sightings[sighter.id].last_seen, timestamp
            )
            self._sightings[sighter.id].count += 1
            if rule_id in self._sightings[sighter.id].alerts:
                bisect.insort(
                    self._sightings[sighter.id].alerts[rule_id],
                    alert,
                    key=lambda a: a["_source"]["@timestamp"],
                )
            else:
                self._sightings[sighter.id].alerts[rule_id] = [alert]

            if timestamp > self._latest:
                self._latest = timestamp

            if (level := alert["_source"]["rule"]["level"]) > self._sightings[
                sighter.id
            ].max_rule_level:
                self._sightings[sighter.id].max_rule_level = level
        else:
            self._sightings[sighter.id] = SightingsCollector.Meta(
                observable_id=self._observable_id,
                sighter_name=sighter.name,
                first_seen=timestamp,
                last_seen=timestamp,
                count=1,
                alerts={str(rule_id): [alert]},
                max_rule_level=alert["_source"]["rule"]["level"],
            )
            self._latest = timestamp

    def observable_id(self):
        return self._observable_id

    def collated(self):
        return self._sightings

    def last_sighting_timestamp(self):
        return self._latest

    @cache
    def max_rule_level(self):
        return max(sighting.max_rule_level for sighting in self._sightings.values())

    @cache
    def first_seen(self, rule_id: str | None = None):
        if rule_id is None:
            return min(sighting.first_seen for sighting in self._sightings.values())
        else:
            return min(self._alerts_timestamps_sorted(rule_id))

    @cache
    def last_seen(self, rule_id: str | None = None):
        if rule_id is None:
            return max(sighting.last_seen for sighting in self._sightings.values())
        else:
            return max(self._alerts_timestamps_sorted(rule_id))

    @cache
    def alerts_by_rule_id(self):
        """
        Return a dict with alerts grouped by rule_id

        The keys are Wazuh rule IDs as strings (since they are strings in Wazuh). The values are arrays of dicts, containing all alerts with that rule ID.
        Example: { "1234": [{…}, {…}] "1235": […] }
        """
        return {
            rule_id: sorted(
                alerts,
                key=lambda a: a["_source"]["@timestamp"],
            )
            for rule_id in {
                rule_id
                for sighting in self._sightings.values()
                for rule_id in sighting.alerts
            }
            for alerts in (
                [
                    alert
                    for alerts in [
                        sighting.alerts[rule_id]
                        for sighting in self._sightings.values()
                        if rule_id in sighting.alerts
                    ]
                    for alert in alerts
                ],
            )
        }

    @cache
    def alerts_by_rule_id_meta(self):
        """
        Returns a dict with alerts by rule_id, along with some other metadata
        """
        return {
            rule_id: {
                "alerts": sorted(
                    alerts,
                    key=lambda a: a["_source"]["@timestamp"],
                ),
                "first_seen": min(alert["_source"]["@timestamp"] for alert in alerts),
                "last_seen": max(alert["_source"]["@timestamp"] for alert in alerts),
                "sighters": [
                    sighter
                    for sighter, sighting in self._sightings.items()
                    if rule_id in sighting.alerts
                ],
            }
            for rule_id in {
                rule_id
                for sighting in self._sightings.values()
                for rule_id in sighting.alerts
            }
            for alerts in (
                [
                    alert
                    for alerts in [
                        sighting.alerts[rule_id]
                        for sighting in self._sightings.values()
                        if rule_id in sighting.alerts
                    ]
                    for alert in alerts
                ],
            )
        }

    @cache
    def alerts_by_sighter_meta(self):
        return {
            sighter_id: {
                "alerts": sorted(
                    [alert for alerts in meta.alerts.values() for alert in alerts],
                    key=lambda a: a["_source"]["@timestamp"],
                ),
                "sighter_name": meta.sighter_name,
            }
            for sighter_id, meta in self._sightings.items()
        }

    @cache
    def alerts(self):
        return [
            alert
            for sighting in self._sightings.values()
            for alerts in sighting.alerts.values()
            for alert in alerts
        ]
