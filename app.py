from flask import Flask, request
from flask_json import FlaskJSON, JsonError, json_response

from urllib.parse import urlparse, urlencode
import hmac
import base64
from hashlib import sha256

from settings_local import SIGN_SECRET

app = Flask(__name__)
json_app = FlaskJSON(app)

app.config['JSON_ADD_STATUS'] = True
app.config['JSON_DATETIME_FORMAT'] = '%d/%m/%Y %H:%M:%S'


def sign_url(original_url):
    query = '?' + urlparse(original_url).query
    encoded_query = bytes(query, 'utf-8')
    encoded_secret = bytes(SIGN_SECRET, 'utf-8')
    key = hmac.new(encoded_secret, encoded_query, sha256).digest()
    signature = base64.b64encode(key)
    query_signature = {'signature': signature.decode('utf-8')}
    signed_url = original_url + '&' + urlencode(query_signature)
    return signed_url


@app.route('/', methods=['POST'])
def sign_url_view():
    data = request.get_json(force=True)

    if 'url' not in data:
        return json_response(error={'missing url in data'})

    original_url = data['url']
    signed_url = sign_url(original_url)

    return json_response(signed_url=signed_url)
