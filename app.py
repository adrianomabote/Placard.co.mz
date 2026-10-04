"""Gunicorn compatibility entry point for Render's app:app start command."""

from main import app

__all__ = ["app"]