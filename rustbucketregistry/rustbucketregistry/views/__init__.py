# Views package initialization
from .register import register_rustbucket
from .home import index, detail
from .logsinks import logsinks_view, logsink_api

__all__ = [
    'register_rustbucket',
    'index', 'detail',
    'logsinks_view', 'logsink_api'
]
