"""Network side of the migration: ``apply`` and
``rollback`` against the content manager API of the Wazuh indexer.

The HTTP modules of the standard library are imported lazily by
:mod:`rmig.api.client`, only when a networked command runs: ``scan``, ``plan``
and ``build`` never load them.
"""
