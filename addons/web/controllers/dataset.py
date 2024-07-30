# Part of Odoo. See LICENSE file for full copyright and licensing details.

import base64
import io
import json
import logging
import warnings
import functools
import odoo
import odoo.modules.registry
from odoo.service import db

from ..controllers.database import SECRET_KEY
from ..controllers.services import Service
from ..controllers.utils import generate_hmac_sha512, is_greater_than_3_minutes
from odoo import http
from odoo.api import call_kw, Environment
from odoo.http import request, Response
from odoo.models import check_method_name
from .utils import clean_action
from odoo.modules import get_resource_path
from odoo.tools.mimetypes import guess_mimetype
try:
    from werkzeug.utils import send_file
except ImportError:
    from odoo.tools._vendor.send_file import send_file



_logger = logging.getLogger(__name__)


class DataSet(http.Controller):

    @http.route('/web/dataset/search_read', type='json', auth="user")
    def search_read(self, model, fields=False, offset=0, limit=False, domain=None, sort=None):
        return request.env[model].web_search_read(domain, fields, offset=offset, limit=limit, order=sort)

    @http.route('/web/dataset/load', type='json', auth="user")
    def load(self, model, id, fields):
        warnings.warn("the route /web/dataset/load is deprecated and will be removed in Odoo 17. Use /web/dataset/call_kw with method 'read' and a list containing the id as args instead", DeprecationWarning)
        value = {}
        r = request.env[model].browse([id]).read()
        if r:
            value = r[0]
        return {'value': value}

    def _call_kw(self, model, method, args, kwargs):
        check_method_name(method)
        return call_kw(request.env[model], method, args, kwargs)

    @http.route('/web/dataset/call', type='json', auth="user")
    def call(self, model, method, args, domain_id=None, context_id=None):
        warnings.warn("the route /web/dataset/call is deprecated and will be removed in Odoo 17. Use /web/dataset/call_kw with empty kwargs instead", DeprecationWarning)
        return self._call_kw(model, method, args, {})

    @http.route(['/web/dataset/call_kw', '/web/dataset/call_kw/<path:path>'], type='json', auth="user")
    def call_kw(self, model, method, args, kwargs, path=None):
        return self._call_kw(model, method, args, kwargs)

    @http.route('/web/dataset/call_button', type='json', auth="user")
    def call_button(self, model, method, args, kwargs):
        action = self._call_kw(model, method, args, kwargs)
        if isinstance(action, dict) and action.get('type') != '':
            return clean_action(action, env=request.env)
        return False

    @http.route('/web/dataset/resequence', type='json', auth="user")
    def resequence(self, model, ids, field='sequence', offset=0):
        """ Re-sequences a number of records in the model, by their ids

        The re-sequencing starts at the first model of ``ids``, the sequence
        number is incremented by one after each record and starts at ``offset``

        :param ids: identifiers of the records to resequence, in the new sequence order
        :type ids: list(id)
        :param str field: field used for sequence specification, defaults to
                          "sequence"
        :param int offset: sequence number for first record in ``ids``, allows
                           starting the resequencing from an arbitrary number,
                           defaults to ``0``
        """
        m = request.env[model]
        if not m.fields_get([field]):
            return False
        # python 2.6 has no start parameter
        for i, record in enumerate(m.browse(ids)):
            record.write({field: i + offset})
        return True
    
    @http.route('/web/company/update_logo', type='http', auth='none', methods=['POST'], csrf=False)
    def update_company_logo(self, company_id, logo_path, dbname, privatekey, timestamp):
        try:
             #Check timestamp
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
            )

            if dbname not in db.list_dbs():
                return http.Response(
                    status=404,
                    response=json.dumps({'error': f"Database {dbname} not found"}),
                    content_type='application/json'
                )
            
            message = dbname + Service.get_api_key(dbname)

            hash_message = generate_hmac_sha512(SECRET_KEY, message)

            if (privatekey != hash_message):
                return http.Response(
                    json.dumps({
                        'error': 'private key incorrect'
                    }),
                    status=400,
                    mimetype='application/json'
                ) 
            #Get file logo from request
            logo_file = request.httprequest.files.get('logo_path')
           
            #print(f"Logo File: {type(logo_file)}")
            if not logo_file:
                error = "No logo file provided."
                return http.Response(
                    status=400,
                    response=json.dumps({'success': False, 'error': error}),
                    content_type='application/json'
                )

            #Decode binary file into base64
            logo_base64 = base64.b64encode(logo_file.read()).decode('utf8')

            model = 'res.company'
            method = 'write'
            args = [{int(company_id)}, {'logo': logo_base64}]
            kwargs = {}
            
            #Open connection to db
            registry = odoo.modules.registry.Registry(dbname)
            cr = registry.cursor()
            uid = 1 # default superuser
            self.env = Environment(cr, uid, {})

            check_method_name(method)
            call_kw(self.env[model], method, args, kwargs)
            
            #Commit change
            self.env.cr.commit()

            #Close connection
            self.env.cr.close()
                            
            return http.Response(
                    status=200,
                    response=json.dumps({'success': True, 'message': "Update logo successfully"}),
                    content_type='application/json'
                )             
        except Exception as e:
            error = f"Error stopping database: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )
        
        
    @http.route('/web/company/get_logo', type='http', auth='none', methods=['GET'], csrf=False,  website=True)
    def get_company_logo(self, company_id, dbname, privatekey, timestamp, **kw):    
        #Check timestamp
        if (is_greater_than_3_minutes(timestamp) == False):
            return http.Response(
                json.dumps({"error": "Invalid time"}),
                status=400,
                content_type='application/json'
        )

        if dbname not in db.list_dbs():
            return http.Response(
                status=404,
                response=json.dumps({'error': f"Database {dbname} not found"}),
                content_type='application/json'
            )
            
        message = dbname + Service.get_api_key(dbname)

        hash_message = generate_hmac_sha512(SECRET_KEY, message)

        if (privatekey != hash_message):
            return http.Response(
                json.dumps({
                    'error': 'private key incorrect'
                }),
                status=400,
                mimetype='application/json'
            )
        
        imgname = 'logo'
        imgext = '.png'
        placeholder = functools.partial(get_resource_path, 'web', 'static', 'img')
        dbname = dbname

        if not dbname:
            response = http.Stream.from_path(placeholder(imgname + imgext)).get_response()
        else:
            try:
                # create an empty registry
                registry = odoo.modules.registry.Registry(dbname)
                with registry.cursor() as cr:
                    company = company_id
                    cr.execute("""SELECT logo_web, write_date
                                        FROM res_company
                                       WHERE id = %s
                                   """, (company,))
                        
                    row = cr.fetchone()
                    if row and row[0]:
                        image_base64 = base64.b64decode(row[0])
                        image_data = io.BytesIO(image_base64)
                        mimetype = guess_mimetype(image_base64, default='image/png')
                        imgext = '.' + mimetype.split('/')[1]
                        if imgext == '.svg+xml':
                            imgext = '.svg'
                        response = send_file(
                            image_data,
                            request.httprequest.environ,
                            download_name=imgname + imgext,
                            mimetype=mimetype,
                            last_modified=row[1],
                            response_class=Response,
                        )
                    else:
                        response = http.Stream.from_path(placeholder('nologo.png')).get_response()
            except Exception:
                response = http.Stream.from_path(placeholder(imgname + imgext)).get_response()

        return response