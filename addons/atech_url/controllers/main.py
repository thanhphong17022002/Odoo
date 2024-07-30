
from odoo import http
from odoo.http import request
from werkzeug.utils import redirect

class MyURLController(http.Controller):

        @http.route('/web/database/manager', type='http', auth='public')
        def manage_db_redirect(self, **kwargs):
                return redirect('/web/access-denied')
