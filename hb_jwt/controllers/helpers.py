from odoo.http import request

CONTENT_TYPE = {'content_type': 'application/json'}
STATUS_OK = {'status': 200}
STATUS_ERROR = {'status': 422}
STATUS_UNAUTHORIZED = {'status': 401}

GET_PARAMS = {
    'type':'http',
    'csrf':False,
    'cors':"*",
    'auth': 'none',
    'save_session':False,
    'methods':["GET"]
}

POST_PARAMS = {
    'type':'http',
    'csrf':False,
    'cors':"*",
    'auth': 'none',
    'save_session':False,
    'methods':["POST"]
}
