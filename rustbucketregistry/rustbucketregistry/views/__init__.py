# Views package initialization
from .register import register_rustbucket
from .home import index, about, detail
from .logsinks import logsinks_view, logsink_api

__all__ = [
    'register_rustbucket',
    'index', 'about', 'detail',
    'logsinks_view', 'logsink_api'
]
