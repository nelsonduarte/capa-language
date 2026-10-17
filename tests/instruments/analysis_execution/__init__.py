"""Instrument (b): analysis versus execution.

A labelled program is ANALYSED and never run. Its TWIN replaces the one
secret source by a public marker and runs on every backend; the verdict
says whether the analysis flagged what the execution delivers. Fail-closed
in both directions: a twin without a marker, with more than one source,
or still carrying any secret source is never a CLEAN and is never run.
"""
