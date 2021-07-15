CLIENT_ID = ''
KEY_VAULT_URI = ''
VAULT_SECRET = ''
TENANT_ID = ''


class KeyVault:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.key_vault_uri = KEY_VAULT_URI
        self.vault_secret = VAULT_SECRET
        self.tenant_id = TENANT_ID
        self.auth = self.getAuth2()
        self.api_version = "7.0"

    def setSecret(self, secret_name, secret_value):
        """ Set Secret key """
        r = requests.put('{}/secrets/{}?api-version={}'.format(KEY_VAULT_URI, secret_name, self.api_version),
                         data=json.dumps({"value": secret_value}),
                         headers=self.getHeader())
        return r.json()

    def getSecret(self, secret_name, secret_version=''):
        """ Get Secret Key """
        r = requests.get('{}/secrets/{}/{}?api-version={}'.format(self.key_vault_uri, secret_name,
                                                                   secret_version,self.api_version),
                         headers=self.getHeader())
        result = r.json()
        if 'value' in result.keys():
            return result["value"]
        else:
            return json.dumps({"result": False, "message": "Secret not found"})

    def getAuth(self):
        """ Custom Rest API Auth """
        data = {"grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.vault_secret,
                "resource": "https://vault.azure.net"
                }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        r = requests.post("https://login.windows.net/{}/oauth2/token".format(self.tenant_id), data=data,
                          headers=headers)
        access_token = r.json()['access_token']
        return access_token

    def getAuth2(self):
        """ Azure Key Vault Python Library"""
        from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
        from azure.common.credentials import ServicePrincipalCredentials

        credentials = ServicePrincipalCredentials(
            client_id=self.client_id,
            secret=self.vault_secret,
            tenant=self.tenant_id,
            resource="https://vault.azure.net"
        )
        token = credentials.token
        return token['token_type'], token['access_token']

    def getHeader(self):
        return {"Authorization": "{} {}".format(self.auth[0], self.auth[1]), 'Content-Type': 'application/json'}

    def getVersion(self, data):
        return data['id'].split('/')[-1]

    def getVName(self, data):
        return data['id'].split('/')[-2]
