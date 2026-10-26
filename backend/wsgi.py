"""WSGI entry point for a production server behind a trusted TLS proxy."""

from .app import create_app

app = create_app()
