import requests
import json
from .utils import log_error
import time
import re
import aiohttp
import asyncio
from cachetools import TTLCache
import logging
import unittest
import traceback
import datetime

class TestDiscordWebhook(unittest.TestCase):
    def test_send_message(self):
        webhook = DiscordWebhook(url="https://discord.com/api/webhooks/...")
        self.assertIsNone(webhook.send_message("Hello World"))

    def test_invalid_url(self):
        with self.assertRaises(InvalidWebhookURLError):
            webhook = DiscordWebhook(url="https://invalid.url")
            webhook._validate_url()

    def test_send_message(self):
        assert self.send_message("Test message") is not None

    def test_get_webhook_info(self):
        info = self.get_webhook_info()
        assert info is not None
        assert 'id' in info

class WebhookException(Exception):
    def __init__(self, message=None, code=None, context=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.code = code
        self.context = context
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Erro: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.context:
            error_message += f" (Contexto: {self.context})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message
    
    def get_details(self):
        details = {
            'message': self.message,
            'code': self.code,
            'context': self.context,
            'traceback': self.traceback
        }
        return details

    def log_error(self, logger):
        logger.error(self.__str__())

class WebhookNotFoundError(WebhookException):
    def __init__(self, message=None, code=None, context=None, *args):
        super().__init__(message, code, context, *args)

    def __str__(self):
        return f"Webhook Not Found Error: {super().__str__()}"

    def log_error(self, logger):
        logger.error(self.__str__())

class RateLimitExceededError(WebhookException):
    def __init__(self, message=None, code=None, retry_after=None, context=None, *args):
        super().__init__(message, code, context, *args)
        self.retry_after = retry_after
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Rate Limit Exceeded Error: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} segundos)"
        if self.context:
            error_message += f" (Contexto: {self.context})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        details = {
            'message': self.message,
            'code': self.code,
            'retry_after': self.retry_after,
            'context': self.context,
            'traceback': self.traceback
        }
        return details

    def log_error(self, logger):
        logger.error(self.__str__())

class InvalidWebhookURLError(WebhookException):
    def __init__(self, message=None, code=None, url=None, context=None, *args):
        super().__init__(message, code, context, *args)
        self.url = url
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Invalid Webhook URL Error: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.context:
            error_message += f" (Contexto: {self.context})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        details = {
            'message': self.message,
            'code': self.code,
            'url': self.url,
            'context': self.context,
            'traceback': self.traceback
        }
        return details

    def log_error(self, logger):
        logger.error(self.__str__())


class AsyncDiscordWebhook:
    def __init__(self, url, username=None, avatar_url=None, user_agent=None, timeout=None):
        self.url = url
        self.username = username
        self.avatar_url = avatar_url
        self.user_agent = user_agent
        self.timeout = timeout
        self._validate_url()

    async def send_messages_batch(self, messages, tts=False):
        for message in messages:
            await self.send_message(message, tts)
            await asyncio.sleep(0.5)  

    async def send_message(self, content, tts=False):
        async with aiohttp.ClientSession() as session:
            data = {
                "content": content,
                "username": self.username,
                "avatar_url": self.avatar_url,
                "tts": tts
            }
            await self._post_data(session, data)

    async def _post_data(self, session, data, retries=3, delay=5, custom_headers=None):
        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        if custom_headers:
            headers.update(custom_headers)

        for attempt in range(retries):
            try:
                async with session.post(self.url, json=data, headers=headers, timeout=self.timeout) as response:
                    if response.status == 429:  
                        retry_after = int(response.headers.get('Retry-After', delay))
                        await asyncio.sleep(retry_after)
                        continue
                    response.raise_for_status()
                    return await response.text()  
            except aiohttp.ClientError as e:
                log_error(f"Erro ao enviar dados: {e}", self.log_errors)  
                if attempt < retries - 1:
                    await asyncio.sleep(delay)
                else:
                    raise

    def _validate_url(self):
        regex = re.compile(
            r'^(https?://)?(www\.)?discord(app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+$'
        )
        if not regex.match(self.url):
            raise InvalidWebhookURLError("Invalid Discord webhook URL.")
        
class DiscordWebhook:
    def __init__(self, url, username=None, avatar_url=None, log_errors=False, timeout=None, proxies=None, user_agent=None, verbose=False):
        self.url = url
        self.username = username
        self.avatar_url = avatar_url
        self.log_errors = log_errors
        self.timeout = timeout
        self.proxies = proxies
        self.user_agent = user_agent
        self.verbose = verbose
        self.session = requests.Session()
        self._validate_url()

    def debug_info(self):
        return {
            'url': self.url,
            'username': self.username,
            'avatar_url': self.avatar_url,
            'timeout': self.timeout,
            'proxies': self.proxies,
            'user_agent': self.user_agent
        }
    
    def set_timeout(self, timeout):
        self.timeout = timeout

    def set_retries(self, retries):
        self.retries = retries
        
    def set_proxy(self, proxy_url):
        self.proxies = {"http": proxy_url, "https": proxy_url}

    def send_rich_embed(self, title, description, fields=None, author=None, footer=None, image_url=None, thumbnail_url=None, timestamp=None):
        embed = {
            "title": title,
            "description": description,
            "fields": fields or [],
            "author": {"name": author} if author else None,
            "footer": {"text": footer} if footer else None,
            "image": {"url": image_url} if image_url else None,
            "thumbnail": {"url": thumbnail_url} if thumbnail_url else None,
            "timestamp": timestamp
        }
        data = {"embeds": [embed]}
        self._post_data(data)
    def modify_webhook(self, name=None, avatar=None):
        data = {}
        if name:
            data['name'] = name
        if avatar:
            import base64
            with open(avatar, 'rb') as image:
                data['avatar'] = 'data:image/png;base64,' + base64.b64encode(image.read()).decode('utf-8')

        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        
        if self.verbose:
            print(f"Modificando webhook {self.url}")
            print(f"Dados: {data}")
            print(f"Cabeçalhos: {headers}")
        
        try:
            response = requests.patch(self.url, json=data, timeout=self.timeout, proxies=self.proxies, headers=headers)
            response.raise_for_status()
            if self.verbose:
                print(f"Resposta: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            log_error(f"Erro ao modificar webhook: {e}", self.log_errors)

    def send_message(self, content, tts=False):
        data = {
            "content": content,
            "username": self.username,
            "avatar_url": self.avatar_url,
            "tts": tts
        }
        self._post_data(data)

    def send_embed(self, title, description, title_url=None, color=None, fields=None, footer=None, image_url=None, thumbnail_url=None):
        embed = {
            "title": title,
            "description": description,
            "url": title_url,
            "color": color,
            "fields": fields or [],
            "footer": {"text": footer} if footer else {},
            "image": {"url": image_url} if image_url else {},
            "thumbnail": {"url": thumbnail_url} if thumbnail_url else {}
        }
        data = {"embeds": [embed]}
        self._post_data(data)

    def send_file(self, file_path, content=None):
        with open(file_path, 'rb') as file:
            files = {
                'file': (file_path, file),
                'payload_json': (None, json.dumps({
                    "content": content or '',
                    "username": self.username or '',
                    "avatar_url": self.avatar_url or ''
                }))
            }
            headers = {
                "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
            }
            
            if self.verbose:
                print(f"Enviando arquivo para {self.url}: {file_path}")
                print(f"Cabeçalhos: {headers}")
            
            try:
                response = requests.post(self.url, files=files, timeout=self.timeout, proxies=self.proxies, headers=headers)
                response.raise_for_status()
                if self.verbose:
                    print(f"Resposta: {response.status_code} - {response.text}")
            except requests.RequestException as e:
                log_error(f"Erro ao enviar arquivo: {e}", self.log_errors)

    def _validate_url(self):
        regex = re.compile(
            r'^(https?://)?(www\.)?discord(app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+$'
        )
        if not regex.match(self.url):
            raise InvalidWebhookURLError("Invalid Discord webhook URL.")


    def delete_webhook(self):
        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        
        if self.verbose:
            print(f"Deletando webhook {self.url}")
            print(f"Cabeçalhos: {headers}")
        
        try:
            response = requests.delete(self.url, timeout=self.timeout, proxies=self.proxies, headers=headers)
            response.raise_for_status()
            if self.verbose:
                print(f"Resposta: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            log_error(f"Erro ao deletar webhook: {e}", self.log_errors)

    def get_webhook_info(self):
        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        
        if self.verbose:
            print(f"Obtendo informações do webhook {self.url}")
            print(f"Cabeçalhos: {headers}")
        
        try:
            response = requests.get(self.url, timeout=self.timeout, proxies=self.proxies, headers=headers)
            response.raise_for_status()
            if self.verbose:
                print(f"Resposta: {response.status_code} - {response.text}")
            return response.json()
        except requests.RequestException as e:
            log_error(f"Erro ao obter informações do webhook: {e}", self.log_errors)
            return None

    def test_webhook(self):
        try:
            self.send_message("Webhook testado com sucesso!")
            return True
        except Exception as e:
            log_error(f"Erro ao testar webhook: {e}", self.log_errors)
            return False


    def _post_data(self, data, retries=3, delay=5, custom_headers=None):
        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        if custom_headers:
            headers.update(custom_headers)

        for attempt in range(retries):
            if self.verbose:
                print(f"Enviando dados para {self.url}: Tentativa {attempt + 1}")
                print(f"Cabeçalhos: {headers}")
            
            try:
                response = requests.post(self.url, json=data, timeout=self.timeout, proxies=self.proxies, headers=headers)
                if response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', delay))
                    if self.verbose:
                        print(f"Rate limited. Tentando novamente após {retry_after} segundos...")
                    time.sleep(retry_after)
                    continue
                response.raise_for_status()
                if self.verbose:
                    print(f"Resposta: {response.status_code} - {response.text}")
                break  # Se a requisição for bem-sucedida, sai do loop
            except requests.RequestException as e:
                log_error(f"Erro ao enviar dados: {e}", self.log_errors)
                if attempt < retries - 1:
                    time.sleep(delay)  # Espera antes de tentar novamente
                else:
                    raise

    def is_webhook_active(self):
        try:
            response = requests.head(self.url, timeout=self.timeout, proxies=self.proxies)
            return response.status_code == 200
        except requests.RequestException as e:
            log_error(f"Erro ao verificar o status do webhook: {e}", self.log_errors)
            return False

    async def send_batch_messages(self, messages, tts=False, delay_between=0):
        for message in messages:
            await self.send_message(message, tts)  # Usar await para chamadas assíncronas
            if delay_between > 0:
                await asyncio.sleep(delay_between)  # Usar asyncio.sleep para evitar bloqueio


    def set_custom_headers(self, headers):
        self.custom_headers = headers


    def set_timeout(self, timeout):
        self.timeout = timeout

    def set_proxies(self, proxies):
        self.proxies = proxies

    def set_username(self, username):
        self.username = username

    def set_avatar_url(self, avatar_url):
        self.avatar_url = avatar_url

    def set_user_agent(self, user_agent):
        self.user_agent = user_agent

    def enable_verbose(self):
        self.verbose = True

    def disable_verbose(self):
        self.verbose = False

    def enable_error_logging(self):
        self.log_errors = True

    def disable_error_logging(self):
        self.log_errors = False

class MentioningDiscordWebhook(DiscordWebhook):
    def send_mention(self, content, user_id=None, role_id=None):
        mention = ""
        if user_id:
            mention = f"<@{user_id}>"
        elif role_id:
            mention = f"<@&{role_id}>"
        self.send_message(f"{mention} {content}")

    def add_reaction(self, message_id, emoji):
        url = f"{self.url}/messages/{message_id}/reactions/{emoji}/@me"
        try:
            response = requests.put(url, timeout=self.timeout, proxies=self.proxies)
            response.raise_for_status()
        except requests.RequestException as e:
            log_error(f"Erro ao adicionar reação: {e}", self.log_errors)


class ValidatingDiscordWebhook(DiscordWebhook):
    def send_embed(self, title, description, **kwargs):
        if len(title) > 256:
            raise ValueError("O título do embed excede o limite de 256 caracteres.")
        if len(description) > 2048:
            raise ValueError("A descrição do embed excede o limite de 2048 caracteres.")
        super().send_embed(title, description, **kwargs)


class ExponentialBackoffDiscordWebhook(DiscordWebhook):
    def _post_data(self, data, retries=3, base_delay=5, custom_headers=None):
        headers = {
            "User-Agent": self.user_agent if self.user_agent else "DiscordWebhookClient/1.0"
        }
        if custom_headers:
            headers.update(custom_headers)

        for attempt in range(retries):
            try:
                response = requests.post(self.url, json=data, timeout=self.timeout, proxies=self.proxies, headers=headers)
                if response.status_code == 429:  # Rate limited
                    retry_after = int(response.headers.get('Retry-After', base_delay))
                    time.sleep(retry_after)
                    continue
                response.raise_for_status()
                return response.text  # Adiciona um retorno em caso de sucesso
            except requests.RequestException as e:
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                time.sleep(delay)
                if attempt == retries - 1:
                    raise RateLimitExceededError(f"Rate limit exceeded after {retries} attempts: {e}")
                
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DiscordWebhookClient")

class VerboseDiscordWebhook(DiscordWebhook):
    def __init__(self, url, username=None, avatar_url=None, timeout=None, **kwargs):
        super().__init__(url, username, avatar_url, timeout=timeout, verbose=True, **kwargs)


class CachedDiscordWebhook(DiscordWebhook):
    def __init__(self, url, username=None, avatar_url=None, timeout=None, max_cache_size=128, cache_ttl=300, **kwargs):
        super().__init__(url, username, avatar_url, timeout=timeout, **kwargs)
        self.cache = TTLCache(maxsize=max_cache_size, ttl=cache_ttl)
        self.logger = logging.getLogger("DiscordWebhookClient")

    def clear_cache(self):
        self.cache.clear()

    def send_message(self, content, tts=False):
        cache_key = (content, tts)
        if cache_key in self.cache:
            if self.verbose:
                print("Cache hit. Mensagem não enviada novamente.")
            return self.cache[cache_key]
        try:
            response = super().send_message(content, tts)
            self.cache[cache_key] = response
            return response
        except Exception as e:
            self.logger.error(f"Erro ao enviar mensagem: {e}") 
            raise

class PrivateWebhook(DiscordWebhook):
    def __init__(self, url, username=None, avatar_url=None, token=None, **kwargs):
        super().__init__(url, username, avatar_url, **kwargs)
        self.token = token

    def _get_headers(self):
        headers = super()._get_headers()
        if self.token:
            headers['Authorization'] = f'Bot {self.token}'
        return headers

class WebhookResponseHandler:
    def __init__(self, url, headers=None, timeout=10):
        self.url = url
        self.headers = headers or {}
        self.timeout = timeout

    def handle_response(self, response):
        status_code = response.status_code
        if status_code == 200:
            return response.json()  
        elif status_code == 400:
            raise BadRequestError("Requisição mal formada.")
        elif status_code == 401:
            raise UnauthorizedError("Não autorizado. Verifique suas credenciais.")
        elif status_code == 403:
            raise ForbiddenError("Acesso proibido.")
        elif status_code == 404:
            raise NotFoundError("Recurso não encontrado.")
        elif status_code == 429:
            raise RateLimitExceededError("Limite de requisições excedido.")
        elif status_code == 500:
            raise InternalServerError("Erro interno do servidor.")
        elif status_code == 502:
            raise BadGatewayError("Erro de gateway.")
        elif status_code == 503:
            raise ServiceUnavailableError("Serviço indisponível.")
        elif status_code == 504:
            raise GatewayTimeoutError("Tempo de resposta do gateway esgotado.")
        else:
            raise UnexpectedStatusCodeError(f"Código de status inesperado: {status_code}")

    def send_request(self, method, data=None):
        try:
            response = requests.request(method, self.url, headers=self.headers, json=data, timeout=self.timeout)
            return self.handle_response(response)
        except requests.RequestException as e:
            raise RequestException(f"Erro na requisição: {e}")

class BadRequestError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details  # Informações adicionais sobre o erro

    def __str__(self):
        error_message = f"Bad Request Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class UnauthorizedError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Unauthorized Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class ForbiddenError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Forbidden Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class NotFoundError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Not Found Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class RateLimitExceededError(WebhookException):
    def __init__(self, message=None, code=None, retry_after=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.retry_after = retry_after
        self.details = details

    def __str__(self):
        error_message = f"Rate Limit Exceeded Error: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} segundos)"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class InternalServerError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Internal Server Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class BadGatewayError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Bad Gateway Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class ServiceUnavailableError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Service Unavailable Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class GatewayTimeoutError(WebhookException):
    def __init__(self, message=None, code=None, context=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.details = details

    def __str__(self):
        error_message = f"Gateway Timeout Error: {super().__str__()}"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

class UnexpectedStatusCodeError(WebhookException):
    def __init__(self, message=None, code=None, context=None, status_code=None, *args):
        super().__init__(message, code, context, *args)
        self.status_code = status_code

    def __str__(self):
        error_message = f"Unexpected Status Code Error: {super().__str__()}"
        if self.status_code is not None:
            error_message += f" (Status Code: {self.status_code})"
        return error_message

class RequestException(Exception):
    def __init__(self, message=None, code=None, url=None, method=None, headers=None, response_body=None, status_code=None, context=None, details=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.code = code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.status_code = status_code
        self.context = context
        self.details = details
        self.traceback = traceback.format_exc() if message else None
        self.timestamp = datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro

    def __str__(self):
        error_message = f"Request Error: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Método: {self.method})"
        if self.headers:
            error_message += f" (Cabeçalhos: {self.headers})"
        if self.response_body:
            error_message += f" (Corpo da Resposta: {self.response_body})"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.context:
            error_message += f" (Contexto: {self.context})"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        if self.timestamp:
            error_message += f"\nTimestamp: {self.timestamp}"
        return error_message

    def get_details(self):
        details = {
            'message': self.message,
            'code': self.code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'status_code': self.status_code,
            'context': self.context,
            'details': self.details,
            'traceback': self.traceback,
            'timestamp': self.timestamp
        }
        return details

    def log_error(self, logger):
        logger.error(self.__str__())


class UnauthorizedError(WebhookException):
    def __init__(self, message=None, code=None, context=None, endpoint=None, headers=None, response_body=None, details=None, *args):
        super().__init__(message, code, context, *args)
        self.endpoint = endpoint  
        self.headers = headers 
        self.response_body = response_body  
        self.details = details 

    def __str__(self):
        error_message = f"Unauthorized Error: {self.message}"
        if self.code:
            error_message += f" (Código: {self.code})"
        if self.endpoint:
            error_message += f" (Endpoint: {self.endpoint})"
        if self.headers:
            error_message += f" (Cabeçalhos: {self.headers})"
        if self.response_body:
            error_message += f" (Corpo da Resposta: {self.response_body})"
        if self.details:
            error_message += f" (Detalhes: {self.details})"
        return error_message

    def get_details(self):
        details = {
            'message': self.message,
            'code': self.code,
            'context': self.context,
            'endpoint': self.endpoint,
            'headers': self.headers,
            'response_body': self.response_body,
            'details': self.details,
            'traceback': self.traceback,
            'timestamp': self.timestamp
        }
        return details

    def log_error(self, logger):
        logger.error(self.__str__())


class ForbiddenError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Forbidden Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())


class NotFoundError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Not Found Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class RateLimitExceededError(Exception):
    def __init__(self, message=None, status_code=None, retry_after=None, url=None, method=None, headers=None, response_body=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Rate Limit Exceeded Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} seconds)"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'retry_after': self.retry_after,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class InternalServerError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, retry_after=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.retry_after = retry_after
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Internal Server Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} seconds)"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'retry_after': self.retry_after,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class BadGatewayError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, retry_after=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.retry_after = retry_after
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Bad Gateway Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} seconds)"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'retry_after': self.retry_after,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class ServiceUnavailableError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, retry_after=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.retry_after = retry_after
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Service Unavailable Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} seconds)"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'retry_after': self.retry_after,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class GatewayTimeoutError(Exception):
    def __init__(self, message=None, status_code=None, url=None, method=None, headers=None, response_body=None, retry_after=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.retry_after = retry_after
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  # Adiciona timestamp do erro
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Gateway Timeout Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.retry_after is not None:
            error_message += f" (Retry-After: {self.retry_after} seconds)"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'retry_after': self.retry_after,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())


class UnexpectedStatusCodeError(Exception):
    def __init__(self, message=None, status_code=None, expected_status_codes=None, url=None, method=None, headers=None, response_body=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.status_code = status_code
        self.expected_status_codes = expected_status_codes
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()  
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Unexpected Status Code Error: {self.message}"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.expected_status_codes:
            error_message += f" (Expected Status Codes: {self.expected_status_codes})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'status_code': self.status_code,
            'expected_status_codes': self.expected_status_codes,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())

class RequestException(Exception):
    def __init__(self, message=None, code=None, url=None, method=None, headers=None, response_body=None, status_code=None, context=None, details=None, error_type=None, timestamp=None, *args):
        super().__init__(message, *args)
        self.message = message
        self.code = code
        self.url = url
        self.method = method
        self.headers = headers
        self.response_body = response_body
        self.status_code = status_code
        self.context = context
        self.details = details
        self.error_type = error_type
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat() 
        self.traceback = traceback.format_exc() if message else None

    def __str__(self):
        error_message = f"Request Error: {self.message}"
        if self.code:
            error_message += f" (Code: {self.code})"
        if self.url:
            error_message += f" (URL: {self.url})"
        if self.method:
            error_message += f" (Method: {self.method})"
        if self.headers:
            error_message += f" (Headers: {self.headers})"
        if self.response_body:
            error_message += f" (Response Body: {self.response_body})"
        if self.status_code:
            error_message += f" (Status Code: {self.status_code})"
        if self.context:
            error_message += f" (Context: {self.context})"
        if self.details:
            error_message += f" (Details: {self.details})"
        if self.error_type:
            error_message += f" (Error Type: {self.error_type})"
        if self.timestamp:
            error_message += f" (Timestamp: {self.timestamp})"
        if self.traceback:
            error_message += f"\nTraceback:\n{self.traceback}"
        return error_message

    def get_details(self):
        return {
            'message': self.message,
            'code': self.code,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'response_body': self.response_body,
            'status_code': self.status_code,
            'context': self.context,
            'details': self.details,
            'error_type': self.error_type,
            'timestamp': self.timestamp,
            'traceback': self.traceback
        }

    def log_error(self, logger):
        logger.error(self.__str__())
