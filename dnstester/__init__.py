"""DNStester — an Unbound scalability test harness.

Two cooperating parts:

* **client** (:mod:`dnstester.loadgen`) — an open-loop DNS load generator that
  sends queries at a precise target QPS regardless of response latency, so the
  measured latency is not distorted by coordinated omission.
* **monitor** (:mod:`dnstester.monitor`) — polls ``unbound-control
  stats_noreset`` over SSH on the Unbound host to read how the resolver itself
  is coping (queries handled, cache hit ratio, recursion time, request-list
  saturation).

:mod:`dnstester.ramp` ties them together into a stepwise QPS ramp that records
the full latency-vs-QPS curve and flags the saturation / breaking point.
"""

__version__ = "0.1.0"
