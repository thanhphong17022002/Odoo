
from odoo import http
from odoo.http import request
from werkzeug.utils import redirect


class NewPageController():

    @http.route('/web/access-denied', website=True, auth='public')
    def access_denied(self, **kwargs):
        return request.render('atech_url.templates_access_denied', {})