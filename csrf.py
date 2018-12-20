import aiohttp_jinja2

from jinja2 import PackageLoader
from aiohttp import web
from wtforms import ValidationError
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)


class CSRFProtect(dict):

    def __init__(self, app: web.Application, *,
                 params: dict=None):
        dict.__init__(self, params or {})
        # super(CSRFProtect, self).__init__()
        self._app = app
        self._name = 'csrf_token'
        self._init_app(app)

    def _init_app(self, app: web.Application) -> None:
        setattr(app, 'csrf', self)

        if not hasattr(app, 'config'):
            setattr(app, 'config', {})

        if not hasattr(app, 'jinja_env'):
            _init_aiohttp_jinja2(app)

        @web.middleware
        async def csrf_protect(request, handler):
            self.request = request
            if not app.config['CSRF_ENABLED']:
                return await handler(request)

            if not app.config['CSRF_CHECK']:
                return await handler(request)

            if request.method not in app.config['CSRF_METHODS']:
                return await handler(request)

            try:
                self._csrf_validate(
                    self._get_csrf_token(request))
            except ValidationError as e:
                return await self._error_response(e.args[0])

            return await handler(request)

        app.config.setdefault('CSRF_CHECK', True)
        app.config.setdefault('CSRF_ENABLED', True)
        app.config.setdefault('CSRF_TIME_LIMIT', 3600)
        app.config.setdefault('CSRF_SSL_STRICT', True)
        app.config.setdefault('CSRF_FIELD_NAME', 'CSRF_TOKEN')
        app.config.setdefault('CSRF_HEADERS', ['X-CSRFToken', 'X-CSRF-Token'])
        app.config.setdefault('CSRF_AUTH_SALT', 'aiohttp_csrf_auth_salt')
        app.config['SECRET_KEY'] = app.config.get(
            'SECRET_KEY', 'aiohttp_csrf_secret_key')
        app.config['CSRF_METHODS'] = set(app.config.get(
            'CSRF_METHODS', ['POST', 'PUT', 'PATCH', 'DELETE']))
        app.jinja_env.globals['csrf_token'] = self._csrf_generate
        app.middlewares.append(csrf_protect)

    def _csrf_generate(self):
        secret_key = self._app.config['SECRET_KEY']
        expires_in = self._app.config.get('CSRF_TOKEN_EXPIRES') or self._app.config[
            'CSRF_TIME_LIMIT']
        s = Serializer(secret_key, expires_in=expires_in)
        return s.dumps({'name': self._name}).decode()

    async def _error_response(self, msg):
        return web.json_response({'status': -1, 'msg': msg})

    def _csrf_validate(self, token):
        if token is None:
            raise ValidationError('The CSRF token is missing.')

        s = Serializer(self._app.config['SECRET_KEY'])

        try:
            data = s.loads(token)
        except SignatureExpired:
            # valid token, but expired
            raise ValidationError('The CSRF token has expired.')
        except BadSignature:
            # invalid token
            raise ValidationError('The CSRF token is invaild.')
        return data['name'] == self._name

    def _get_csrf_token(self, request):
        csrf_field_name = self._app.config['CSRF_FIELD_NAME']
        csrf_token = request.headers.get(csrf_field_name)

        if csrf_token:
            return csrf_token

        for header_name in self._app.config['CSRF_HEADERS']:
            csrf_token = request.headers.get(header_name)
            if csrf_token:
                return csrf_token

        return None


def _init_aiohttp_jinja2(app: web.Application) -> None:
    async def processors(request):
        return {}

    jinja_env = aiohttp_jinja2.setup(
        app, loader=PackageLoader('templates'),
        context_processors=[processors, aiohttp_jinja2.request_processor])

    setattr(app, 'jinja_env', jinja_env)


def setup(app):
    CSRFProtect(app)
