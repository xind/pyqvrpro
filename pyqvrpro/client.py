import base64
import requests
import untangle
from urllib.parse import quote, urlencode

API_VERSION = '1.2.0'


class Client(object):
    def __init__(self, user, password, host, protocol='http', port=8080, verifyssl=True):
        """Initialize QVR client."""

        self._user = user
        self._password = base64.b64encode(password.encode('ascii'))
        self._host = host
        self._protocol = protocol
        self._port = port
        self._verifyssl = verifyssl
        self._authenticated = False
        self._session_id = None
        self._qvrpro_uri = '/qvrpro'

        self._is_qvrpro()
        self.connect()

    def _is_qvrpro(self):
        entry_url = self._get_endpoint_url('/qvrentry')
        response = requests.get(entry_url)
        responseobj = response.json()
        if responseobj.get('fw_web_ui_prefix', '') == 'qvrpro':
            self._qvrpro_uri = '/qvrpro'
        else:
            self._qvrpro_uri = '/qvrelite'

    def connect(self):
        """Login to QVR Pro."""

        login_url = self._get_endpoint_url('/cgi-bin/authLogin.cgi')

        params = {
            'user': self._user,
            'pwd': self._password,
            'serviceKey': 1,
            'verify': self._verifyssl
        }

        response = requests.get(login_url, params=params)

        responseobj = untangle.parse(
            response.content.decode(response.encoding)).QDocRoot

        self._authenticated = bool(int(responseobj.authPassed.cdata))

        if not self.authenticated:
            raise AuthenticationError(msg='Authentication failed.')

        self._session_id = responseobj.authSid.cdata

    def list_cameras(self):
        """Get a list of configured cameras."""

        return self._get(f'{self._qvrpro_uri}/camera/list')

    def get_capability(self, ptz=False):
        """Get camera capability."""

        capability = 'get_camera_capability' if ptz else 'get_event_capability'

        params = {
            'act': capability
        }

        return self._get(f'{self._qvrpro_uri}/camera/capability', params)

    def get_snapshot(self, camera_guid):
        """Get a snapshot from specified camera."""

        return self._get(f'{self._qvrpro_uri}/camera/snapshot/{camera_guid}')

    def get_channel_list(self):
        """Get a list of available channels."""

        resp = self._get(f'{self._qvrpro_uri}/qshare/StreamingOutput/channels')

        if "message" in resp.keys():
            if resp["message"] == "Insufficient permission.":
                raise InsufficientPermissionsError(
                    "User must have Surveillance Management permission")

        return resp

    def get_channel_streams(self, guid):
        """Get streams for a specific channel."""
        url = f'{self._qvrpro_uri}/qshare/StreamingOutput/channel/{guid}/streams'

        return self._get(url)

    def get_channel_live_stream(self, guid, stream=0, protocol='hls'):
        """Get a live stream for a specific channel."""
        if protocol not in ('hls', 'rtmp', 'rtsp'):
            return ''

        url = f'{self._qvrpro_uri}/qshare/StreamingOutput' \
              f'/channel/{guid}/stream/{stream}/liveStream'

        body = {
            'protocol': protocol
        }

        return self._post(url, json=body)

    def delete_channel_live_stream(self, guid, stream='rtsp', token=''):
        """Delete a live stream for a specific channel."""

        body = None
        if stream != 'rtsp':
            body = {
                "token": token
            }

        url = f'{self._qvrpro_uri}/qshare/StreamingOutput' \
            f'/channel/{guid}/stream/{stream}/liveStream'
        return self._delete(url, json=body)

    def start_recording(self, guid):
        """Start recording a specific channel."""
        url = f'{self._qvrpro_uri}/camera/mrec/{guid}/start'

        return self._put(url)

    def stop_recording(self, guid):
        """Start recording a specific channel."""
        url = f'{self._qvrpro_uri}/camera/mrec/{guid}/stop'

        return self._put(url)

    def get_recording(self, timestamp, camera_guid, channel_id=0, pre_period=10000, post_period=0):
        """
            Get a recording from specified camera. 
            Timestamp in UTC time
            pre and post period in miliseconds
        """
        url = '/qvrpro/camera/recordingfile/{}/{}'.format(camera_guid, channel_id)
        params = {
            "time": timestamp,
            "post_period": post_period,
            "pre_period": pre_period
        }
        return self._get(url, params)

    def get_vault_list(self):

        return self._get(f'{self._qvrpro_uri}/qvrip/Vault/getVaultList')

    def check_vault_name(self, name):
        """Check whether the vault_name has been used."""
        params = {
            'vault_name': name
        }

        return self._get(f'{self._qvrpro_uri}/qvrip/Vault/checkVaultName', params)

    def create_vault(self, json):
        url = f'{self._qvrpro_uri}/qvrip/Vault/addVault'

        return self._post(url, json=json)

    def update_vault(self, json):
        url = f'{self._qvrpro_uri}/qvrip/Vault/modifyVault'

        return self._put(url, json=json)

    def delete_vault(self, vault_id):
        url = f'{self._qvrpro_uri}/qvrip/Vault/removeVault'
        body = {
            "vault": {
                "vault_id_list": [vault_id]
            }
        }
        return self._post(url, json=body)

    def disable_vault(self, vault_id):
        # NOTE: As of QVR Pro 2.4.1, sometimes this call will succeed but respond with a 500 error.
        body = {
            "vault": {
                "vault_id": vault_id,
                "enable": False
            }
        }
        return self.update_vault(body)['ReturnStatus']['statusCode'] == 0

    def bind_camera_to_vault(self, vault_id, channel_index, guid, channel_name):
        body = {
            "vault": {
                "vault_id": vault_id,
                "enable": True,
                "channel_guid_list": [
                    {
                        "channel_index": channel_index,
                        "guid": guid,
                        "name": channel_name
                    }
                ]
            }
        }
        return self.update_vault(body)

    def send_metadata(self, vault_id, body):
        url = f'{self._qvrpro_uri}/qvrip/Event/recvNotify/Generic/{vault_id}'
        return self._post(url, json=body)

    def _get_iva_license_plate_url(self):
        url = f'/iva/v1/vehicle/license_plate/qsauth_type/0/qsauth_token/{self._session_id}'
        return url

    def query_iva_license_plate(self, params):
        url = f'{self._qvrpro_uri}{self._get_iva_license_plate_url}'
        return self._get(url, params=params)

    def post_iva_license_plate(self, body):
        url = f'{self._qvrpro_uri}{self._get_iva_license_plate_url}'
        return self._post(url, json=body)

    def _parse_response(self, resp):
        """Return response depending on content type."""
        if not resp.ok:
            self._authenticated = False
            raise QVRResponseError(resp.content.decode('UTF-8'))

        content_type = resp.headers['content-type']

        if content_type == 'application/json':
            return resp.json()

        if content_type == 'image/jpeg':
            return resp.content

        return resp

    def _get(self, uri, params={}):
        """Perform GET request"""

        default_params = {
            'sid': self._session_id,
            'ver': API_VERSION,
        }

        url = self._get_endpoint_url(uri)

        encoded_params = urlencode({**default_params, **params}, quote_via=quote)
        full_url = f"{url}?{encoded_params}"

        resp = requests.get(full_url)

        return self._parse_response(resp)

    def _post(self, uri, json):
        """Do POST request."""
        params = {
            'sid': self._session_id,
        }

        url = self._get_endpoint_url(uri)

        resp = requests.post(url, json=json, params=params)

        return self._parse_response(resp)

    def _put(self, uri, json=None):
        """Do POST request."""
        params = {
            'sid': self._session_id,
            'ver': API_VERSION,
        }

        url = self._get_endpoint_url(uri)

        resp = requests.put(url, json=json, params=params)

        return self._parse_response(resp)

    def _delete(self, uri, json):
        """Do DELETE request."""
        params = {
            'sid': self._session_id,
        }

        url = self._get_endpoint_url(uri)

        resp = requests.delete(url, json=json, params=params)

        return resp.ok

    def _get_endpoint_url(self, uri):
        """Get endpoint url."""
        return '{}{}'.format(self._base_url, uri)

    @property
    def authenticated(self):
        """Get authentication status."""
        return self._authenticated

    @property
    def _base_url(self):
        """Get API base URL."""
        return '{}://{}:{}'.format(self._protocol, self._host, self._port)


class AuthenticationError(ConnectionError):
    def __init__(self, msg):
        super().__init__({msg: msg})


class InsufficientPermissionsError(AuthenticationError):
    def __init__(self, msg):
        super().__init__({msg: msg})


class QVRResponseError(ConnectionError):
    def __init__(self, msg):
        super().__init__({msg: msg})
