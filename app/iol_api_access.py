import requests
from getpass import getpass
import datetime as dt


class BearerAuth(requests.auth.AuthBase):
    '''
    Clase auxiliar para manejar la autenticacion con un Bearer token
    '''
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.token
        return r

# URL para obtener el primer par de tokens de la API
TOKEN_URL = "https://api.invertironline.com/token"


class IolApiAccess:

    def __init__(self):
        self.__bearer_token = ""
        self.__refresh_token = ""
        self.__token_exp = None
        self.__refresh_exp = None

        self.__username = ""
        self.__password = ""

    def parse_date(self, date_str):
        '''
        Parseo la fecha que devuileve el servidor como string en
        un objeto datetime. El formato en el que viene es:
        Sat, 29 May 2021 19:18:40 GMT
        '''
        date_obj = dt.datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
        return date_obj

    def update_token_info(self, response_json):
        self.__bearer_token = response_json["access_token"]
        self.__refresh_token = response_json["refresh_token"]
        self.__token_exp = self.parse_date(response_json[".expires"])
        self.__refresh_exp = self.parse_date(response_json[".refreshexpires"])

    def check_token(self):
        '''
        Funcion para checkear que un token no este vencido.
        En caso de estarlo pedir uno nuevo
        '''
        now = dt.datetime.now()
        if now > self.__refresh_exp:
            print("Se vencio el token de refresh, debe autenticarse de nuevo")
            self.authenticate()
        elif now > self.__token_exp:
            # Se vencio el bearer token
            self.refresh_token()

    def authenticate(self):
        #Primero vamos a pedir el usuario y contraseña
        self.__username = input("Usuario: ")
        self.__password = getpass()

        #Armo el diccionario con los parametros
        data = {
            "username": self.__username,
            "password": self.__password,
            "grant_type": "password"
        }

        r = requests.post(url=TOKEN_URL, data=data)

        # Reviso el status code para verificar que todo fue bien
        if r.status_code == 200:
            self.update_token_info(r.json())
        else:
            assert 0, "Algo salio mal. Status Code: %d " % (r.status_code)

    def refresh_token(self):
        #Armo el diccionario con los parametros
        data = {
            "refresh_token": self.__refresh_token,
            "grant_type": "refresh_token"
        }

        r = requests.post(url=TOKEN_URL, data=data)

        # Reviso el status code para verificar que todo fue bien
        if r.status_code == 200:
            self.update_token_info(r.json())
        else:
            assert 0, "Algo salio mal. Status Code: %d " % (r.status_code)

    def get(self, url, params={}):
        """
        Funcion para consultar algun endpoint especifico de la API.
        Manda en los headers el Bearer token
        """
        # Checkeo que el token no se vencio
        self.check_token()

        # Agrego el bearer token a los headers, uso Bearer auth
        # para manejar la autenticacion
        r = requests.get(url=url, params=params,
                         auth=BearerAuth(self.__bearer_token))

        return r
