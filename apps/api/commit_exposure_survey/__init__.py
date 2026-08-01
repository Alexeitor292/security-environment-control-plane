"""Measured survey of the API's response-before-commit exposure (SECP commit-exposure survey).

A survey, never a change: nothing here imports into production, and ``apps/api/secp_api`` is not
modified by this package. See ``scripts/survey/run_api_commit_exposure.py`` for the entry point and
``tests/test_api_commit_exposure_survey.py`` for the proofs that keep the instrument honest.
"""
