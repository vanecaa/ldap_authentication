from django_auth_ldap.backend import LDAPBackend
from django_auth_ldap.config import LDAPSearch
import ldap
import logging
from dotenv import load_dotenv
import os

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    filename='app.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

class MultiLDAPBackend(LDAPBackend):
    def authenticate(self, request, username, password, *args, **kwargs):
        domains = [
            {
                "uri": os.getenv("LDAP1_URI"),
                "bind_dn": os.getenv("LDAP1_BIND_DN"),
                "password": os.getenv("LDAP1_PASSWORD"),
                "search_base": os.getenv("LDAP1_SEARCH_BASE"),
            },
            {
                "uri": os.getenv("LDAP2_URI"),
                "bind_dn": os.getenv("LDAP2_BIND_DN"),
                "password": os.getenv("LDAP2_PASSWORD"),
                "search_base": os.getenv("LDAP2_SEARCH_BASE"),
            },
        ]

        for domain in domains:
            if not all(domain.values()):
                log.error(f"Не все параметры заданы для домена {domain}")
                continue
            try:
                log.info(f"Подключение к домену: {domain['uri']}")
                self.settings.AUTH_LDAP_SERVER_URI = domain["uri"]
                self.settings.AUTH_LDAP_BIND_DN = domain["bind_dn"]
                self.settings.AUTH_LDAP_BIND_PASSWORD = domain["password"]
                self.settings.AUTH_LDAP_USER_SEARCH = LDAPSearch(
                    domain["search_base"],
                    ldap.SCOPE_SUBTREE,
                    "(sAMAccountName=%(user)s)"
                )
                user = super().authenticate(request, username=username, password=password, *args, **kwargs)
                if user:
                    log.info(f"успешная аутентификация {username} через {domain['uri']}")
                    return user

            except ldap.INVALID_CREDENTIALS:
                log.warning(f"неверные данные для {domain['uri']}")
                continue
            except ldap.INVALID_SYNTAX as e:
                log.error(f"значение атрибута{domain['uri']}, указанное клиентом, не соответствует синтаксису, определенному в серверной схеме {e}.")

            except ldap.LDAPError as e:
                log.error(f"ошибка при подключении к {domain['uri']}: {e}")
                continue


        log.warning(f"аутентификация {username} не удалась ни в одном домене")
        return None
