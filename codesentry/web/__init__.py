"""Optional local web workbench; install the web extra to serve it."""


def create_app(data_dir, frontend_dir=None, **kwargs):
    from codesentry.web.app import create_app as factory
    return factory(data_dir, frontend_dir=frontend_dir, **kwargs)


__all__ = ["create_app"]
