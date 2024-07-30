# Part of Odoo. See LICENSE file for full copyright and licensing details.

import datetime
import json
import logging
import os
import re
import tempfile
from lxml import html

from ..controllers.services import Service
from ..controllers.utils import generate_random_string, generate_hmac_sha512, is_greater_than_3_minutes
import odoo
import odoo.modules.registry
from odoo import http
from odoo import http, tools
from odoo.http import content_disposition, dispatch_rpc, request, Response
from odoo.service import db
from odoo.tools.misc import file_open, str2bool, hmac
from odoo.tools.translate import _
from odoo.modules.registry import Registry
from odoo.addons.base.models.ir_qweb import render as qweb_render
from odoo.sql_db import connection_info_for, db_connect

_logger = logging.getLogger(__name__)

DBNAME_PATTERN = '^[a-zA-Z0-9][a-zA-Z0-9_.-]+$'

# list domain accept call api
WHITELIST_DOMAINS = [
    'localhost:8069',
    'api-dev.ezcount.vn',
    'ezinvoice.cc',
    'localhost:3000'
]

from passlib.context import CryptContext

crypt_context = CryptContext(schemes=['pbkdf2_sha512', 'plaintext'],
                             deprecated=['plaintext'],
                             pbkdf2_sha512__rounds=600_000)

DBNAME_PATTERN = '^[a-zA-Z0-9][a-zA-Z0-9_.-]+$'

SECRET_KEY = 'AmazingTech'


# MASTER_PASSWORD = '12345'

# fuction check domain
def domain_validation_required(func):
    def wrapper(*args, **kwargs):
        # Validate domain against whitelist
        if not validate_domain(request):
            # If the domain is not in the whitelist, return an error response
            return http.Response('Domain not allowed', status=403, mimetype='json/application')
        return func(*args, **kwargs)

    return wrapper


def validate_domain(request):
    # Check if the request domain has the domain extension of any domain in the whitelist
    return any(request.httprequest.host.endswith(domain) for domain in WHITELIST_DOMAINS)


class Database(http.Controller):

    def _render_template(self, **d):
        d.setdefault('manage', True)
        d['insecure'] = odoo.tools.config.verify_admin_password('admin')
        d['list_db'] = odoo.tools.config['list_db']
        d['langs'] = odoo.service.db.exp_list_lang()
        d['countries'] = odoo.service.db.exp_list_countries()
        d['pattern'] = DBNAME_PATTERN
        # databases list
        try:
            d['databases'] = http.db_list()
            d['incompatible_databases'] = odoo.service.db.list_db_incompatible(d['databases'])
        except odoo.exceptions.AccessDenied:
            d['databases'] = [request.db] if request.db else []

        templates = {}

        with file_open("web/static/src/public/database_manager.qweb.html", "r") as fd:
            templates['database_manager'] = fd.read()
        with file_open("web/static/src/public/database_manager.master_input.qweb.html", "r") as fd:
            templates['master_input'] = fd.read()
        with file_open("web/static/src/public/database_manager.create_form.qweb.html", "r") as fd:
            templates['create_form'] = fd.read()

        def load(template_name):
            fromstring = html.document_fromstring if template_name == 'database_manager' else html.fragment_fromstring
            return (fromstring(templates[template_name]), template_name)

        return qweb_render('database_manager', d, load)

    @http.route('/web/database/selector', type='http', auth="none")
    @domain_validation_required
    def selector(self, **kw):
        if request.db:
            request.env.cr.close()
        return self._render_template(manage=False)

    @http.route('/web/database/manager', type='http', auth="none")
    @domain_validation_required
    def manager(self, **kw):
        if request.db:
            request.env.cr.close()
        return self._render_template()

    @http.route('/web/database/create', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def create(self, name, lang, password, **post):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])

        # message = name + lang + password + post['login'] + post['phone']

        # hash_message = generate_hmac_sha512(KeySecret,message)

        # if(privatekey != hash_message):
        #     return http.Response(
        #         json.dumps({
        #             'error': 'private key incorrect'
        #         }),
        #         status=400,
        #         mimetype='application/json'
        #     )

        try:
            if not re.match(DBNAME_PATTERN, name):
                raise Exception(
                    _('Invalid database name. Only alphanumerical characters, underscore, hyphen and dot are allowed.'))

            # create random string have length 20
            api_key = generate_random_string(20)

            country_code = post.get('country_code') or False

            dispatch_rpc('db', 'create_database',
                         [name, bool(post.get('demo')), lang, password, post['login'], country_code,
                          post['phone']])

            auth_api_key_model = {
                "user_id": 1,
                "create_uid": 2,
                "write_uid": 2,
                "name": name,
                "key": api_key,
                "create_date": datetime.datetime.now(),
                "write_date": datetime.datetime.now()
            }

            # insert api key to new database
            Service.insert_auth_api_key(dbname=name, data=auth_api_key_model)

            # get module installed in database
            modules = Service.get_modules_from_database(dbname=name, stateModule="installed")

            # country code could be = "False" which is actually True in python
            # request.session.authenticate(name, post['login'], password)
            # request.session.db = name

            return http.Response(
                json.dumps({
                    "api_key": api_key,
                    "modules": modules
                }),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            _logger.exception("Database creation error.")
            error = "Database creation error: %s" % (str(e) or repr(e))
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    @http.route('/web/database/duplicate', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def duplicate(self, name, new_name, neutralize_database=False):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            if not re.match(DBNAME_PATTERN, new_name):
                raise Exception(
                    _('Invalid database name. Only alphanumerical characters, underscore, hyphen and dot are allowed.'))
            dispatch_rpc('db', 'duplicate_database', [name, new_name, neutralize_database])
            if request.db == name:
                request.env.cr.close()  # duplicating a database leads to an unusable cursor
            return request.redirect('/web/database/manager')
        except Exception as e:
            _logger.exception("Database duplication error.")
            error = "Database duplication error: %s" % (str(e) or repr(e))
            return self._render_template(error=error)

    @http.route('/web/database/drop', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def drop(self, name):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            dispatch_rpc('db', 'drop', [name])
            if request.session.db == name:
                request.session.logout()
            return request.redirect('/web/database/manager')
        except Exception as e:
            _logger.exception("Database deletion error.")
            error = "Database deletion error: %s" % (str(e) or repr(e))
            return self._render_template(error=error)

    @http.route('/web/database/backup', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def backup(self, name, backup_format='zip'):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            # odoo.service.db.check_super(MASTER_PASSWORD)
            ts = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            filename = "%s_%s.%s" % (name, ts, backup_format)
            headers = [
                ('Content-Type', 'application/octet-stream; charset=binary'),
                ('Content-Disposition', content_disposition(filename)),
            ]
            dump_stream = odoo.service.db.dump_db(name, None, backup_format)
            response = Response(dump_stream, headers=headers, direct_passthrough=True)
            return response
        except Exception as e:
            _logger.exception('Database.backup')
            error = "Database backup error: %s" % (str(e) or repr(e))
            return self._render_template(error=error)

    @http.route('/web/database/restore', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def restore(self, backup_file, name, copy=False, neutralize_database=False):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            data_file = None
            # db.check_super(MASTER_PASSWORD)
            with tempfile.NamedTemporaryFile(delete=False) as data_file:
                backup_file.save(data_file)
            db.restore_db(name, data_file.name, str2bool(copy), neutralize_database)
            return request.redirect('/web/database/manager')
        except Exception as e:
            error = "Database restore error: %s" % (str(e) or repr(e))
            return self._render_template(error=error)
        finally:
            if data_file:
                os.unlink(data_file.name)

    @http.route('/web/database/start', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def start_database(self, original_name, new_name):
        # Check if the provided master password is valid
        # insecure = tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    db.dispatch('change_admin_password', ["admin", MASTER_PASSWORD])

        try:
            # Check if the provided master password is valid for database operations
            # db.check_super(MASTER_PASSWORD)

            # Check if the renamed database exists
            if new_name in db.list_dbs():
                # Rename the database back to its original name
                db.exp_rename(new_name, original_name)

                return http.Response(
                    status=200,
                    response=json.dumps(
                        {'success': True,
                         'message': f"Database {new_name} has been started and renamed back to {original_name}"}
                    ),
                    content_type='application/json'
                )
            else:
                return http.Response(
                    status=404,
                    response=json.dumps({'success': False, 'message': f"Database {new_name} not found or not renamed"}),
                    content_type='application/json'
                )
        except Exception as e:
            error = f"Error starting database: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )

    @http.route('/api/user/password/forgot', type='json', auth='public', methods=['POST'])
    @domain_validation_required
    def forgot_password(self, email):
        # Find user by email
        user = request.env['res.users'].sudo().search([('email', '=', email)])
        if not user:
            return {'error': 'User not found'}

        # Generate password reset token
        token = request.env['ir.model.data'].sudo().xmlid_to_res_id('base.reset_password_email')
        user.with_context(reset_password=True).sudo().action_reset_password()

        # Send email with password reset link
        template = request.env.ref('auth_signup.reset_password_email')
        template.with_context(lang=user.lang).send_mail(user.id, force_send=True)

        return {'success': True}

    @http.route('/web/database/change_password', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def change_password(self, master_pwd, master_pwd_new):
        try:
            dispatch_rpc('db', 'change_admin_password', [master_pwd, master_pwd_new])
            return request.redirect('/web/database/manager')
        except Exception as e:
            error = "Master password update error: %s" % (str(e) or repr(e))
            return self._render_template(error=error)

    @http.route('/web/database/list', type='json', auth='none')
    @domain_validation_required
    def list(self):
        """
        Used by Mobile application for listing database
        :return: List of databases
        :rtype: list
        """
        return http.db_list()

    # @http.route('/web/database/test_orm_api', type='json', auth="none", methods=['POST'], csrf=False)
    # @domain_validation_required
    # def test_orm_api(self, **post):
    #     headers = request.httprequest.environ
    #     url = 'http://' + headers.get('HTTP_HOST')
    #     try:
    #         if post['column']:
    #             columns = post['column']
    #         else:
    #             columns = []
    #         models = xmlrpc.client.ServerProxy('{}/xmlrpc/2/object'.format(url))
    #         data = models.execute_kw(post["dbname"], post["uid"], post["password"], post['model'], post["action"], [],
    #                                  columns)

    #         return data

    #     except Exception as e:
    #         return http.Response(
    #             json.dumps({"error": e}),
    #             status=200,
    #             mimetype='application/json'
    #         )

    # @http.route('/web/database/test_fetch_api', type='http', auth="api_key", methods=['GET'], csrf=False)
    # @domain_validation_required
    # def test_fetch_api(self):
    #     url = 'https://tiktok.fullstack.edu.vn/api/users/search?q=d&type=less'
    #     try:
    #         # your token here
    #         headers = {
    #             "Authorization": "Bearer <your-access-token>",
    #         }
    #         # send request with headers authrization token
    #         # response = requests.get(url, headers=headers)

    #         response = requests.get(url)
    #         data = response.json()
    #         print(data)
    #         return http.Response(
    #             status=200,
    #             mimetype='application/json'
    #         )
    #     except requests.RequestException as e:
    #         # Handle connection errors or other exceptions here
    #         return http.Response(
    #             json.dumps({'error': "fetch api fail"}),
    #             status=500,
    #             mimetype='application/json'
    #         )

    #     except Exception as e:
    #         # Handle connection errors or other exceptions here
    #         return http.Response(
    #             json.dumps({'error': "orm api fail"}),
    #             status=500,
    #             mimetype='application/json'
    #         )

    # api create api key
    @http.route('/web/database/insert-api-key', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def insert_api_key(self, dbname):
        try:
            # create random string have length 20
            api_key = generate_random_string(20)

            # Tạo dữ liệu để insert vào bảng auth_api_key
            auth_api_key_model = {
                "user_id": 1,
                "create_uid": 2,
                "write_uid": 2,
                "name": dbname,
                "key": api_key,
                "create_date": datetime.datetime.now(),
                "write_date": datetime.datetime.now()
            }

            # Thực hiện insert dữ liệu vào bảng auth_api_key
            Service.insert_auth_api_key(dbname, auth_api_key_model)

            return http.Response(
                status=200,
                response=json.dumps({'api-key': api_key}),
                content_type='application/json'
            )
        except Exception as e:
            error = f"Error inserting api key: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'error': error}),
                content_type='application/json'
            )

    # api get list user
    # @http.route('/web/database/users', type='http', auth="api_key", methods=['GET'], csrf=False)
    # @domain_validation_required
    # def get_users(self, dbname):
    #     try:
    #
    #         # Lấy danh sách người dùng từ bảng res.users
    #         users = Service.get_users_from_database(dbname)
    #
    #         return http.Response(
    #             json.dumps(users),
    #             status=200,
    #             mimetype='application/json'
    #         )
    #     except Exception as e:
    #         error = f"Error getting users: {str(e)}"
    #         return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    @http.route('/web/database/invoices', type='http', auth="api_key", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_invoices(self, dbname):
        try:

            # Lấy danh sách người dùng từ bảng res.users
            invoices = Service.get_invoice_from_database(dbname)

            return http.Response(
                json.dumps(invoices),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            error = "Error getting invoice: %s" % (str(e) or repr(e))
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    @http.route('/web/database/modules', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def install_module(self, dbname, moduleId):
        try:
            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_install()
                    return http.Response(
                        json.dumps({'message': f'install module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )

        except Exception as e:
            error = f"Error install module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/database/modules', type='http', auth="none", methods=['PATCH'], csrf=False)
    @domain_validation_required
    def upgrade_module(self, dbname, moduleId):
        try:
            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_upgrade()
                    return http.Response(
                        json.dumps({'message': f'upgrade module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )
        except Exception as e:
            error = f"Error upgrade module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/database/modules', type='http', auth="none", methods=['DELETE'], csrf=False)
    @domain_validation_required
    def deactive_module(self, dbname, moduleId):
        try:
            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_uninstall()
                    return http.Response(
                        json.dumps({'message': f'deactive module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )
        except Exception as e:
            error = f"Error deactive module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/database/modules', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_modules(self, dbname):
        try:

            module = Service.get_modules_from_database(dbname, None)

            return http.Response(
                json.dumps(module),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            error = f"Error getting module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    # api change password account
    @http.route('/web/database/change_password_v2', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def change_password_v2(self, dbname, email, oldpassword, newpassword, timestamp, privatekey):
        try:
            wsgienv = {
                'interactive': True,
            }

            # register database
            registry = Registry(dbname)

            # Find user by email
            user = registry['res.users'].sudo().search([('login', '=', email)], limit=1)
            if not user:
                return http.Response(
                    status=404,
                    response=json.dumps({'error': f"User with email {email} not found"}),
                    content_type='application/json'
                )

            # Check user password
            pre_uid = user.authenticate(dbname, email, oldpassword, wsgienv)
            if not pre_uid:
                return http.Response(
                    status=401,
                    response=json.dumps({'error': 'Invalid credentials'}),
                    content_type='application/json'
                )

            # hash password
            hash_password = crypt_context.hash if hasattr(crypt_context, 'hash') else crypt_context.encrypt
            newpass = hash_password(newpassword)

            # update password
            Service.update_password(newpass, dbname, pre_uid)

            # Additional code
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            # Check the database exists
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

            return http.Response(
                json.dumps({"message": "Password updated successfully"}),
                status=200,
                content_type='application/json'
            )
        except Exception as e:
            error = f"Error changing password: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'error': error}),
                content_type='application/json'
            )

    # api set account send email
    @http.route('/web/mail_server/setup_outgoing_mail', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def setup_outgoing_mail(self, timestamp, dbname, name, email, password, isDefault, smtp_encryption='ssl',
                            smtp_port=587):
        # check spam call api
        if (is_greater_than_3_minutes(timestamp) == False):
            return http.Response(
                json.dumps({"error": "Invalid time"}),
                status=400,
                content_type='application/json'
            )

        try:
            # Authenticate user and connect to database
            registry = odoo.modules.registry.Registry(dbname)
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, 1, {})

                # Set smtp_user and smtp_pass based on isDefault
                if isDefault.lower() == 'true':
                    # Use default admin credentials
                    smtp_user = 'admin'
                    smtp_pass = 'admin'

                else:
                    smtp_user = email
                    smtp_pass = password

                # Create a new mail server record
                mail_server_vals = {
                    'name': name,
                    'smtp_user': smtp_user,
                    'smtp_pass': smtp_pass,
                    'smtp_host': 'smtp.gmail.com',
                    'smtp_encryption': smtp_encryption,
                    'smtp_port': smtp_port,
                    'smtp_authentication': 'login'
                }
                mail_server = env['ir.mail_server'].create(mail_server_vals)

                # Check if Gmail server settings are valid
                mail_server._check_use_google_gmail_service()

                return http.Response(
                    status=200,
                    response=json.dumps({'success': True, 'message': 'Outgoing mail server setup successful'}),
                    content_type='application/json'
                )
        except Exception as e:
            error = f"Error setting up outgoing mail server: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )

    # ================================================================================================>

    @http.route('/web/databases/create', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def creates(self, privatekey, timestamp, name, lang, password, **post):

        try:
            # check spam call api
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            message = name + post['login']

            # hash message by sha512
            hash_message = generate_hmac_sha512(SECRET_KEY, message)

            if (privatekey != hash_message):
                return http.Response(
                    json.dumps({
                        'error': 'private key incorrect'
                    }),
                    status=400,
                    mimetype='application/json'
                )

            if not re.match(DBNAME_PATTERN, name):
                raise Exception(
                    _('Invalid database name. Only alphanumerical characters, underscore, hyphen and dot are allowed.'))

            # create random string have length 20
            api_key = generate_random_string(20)

            country_code = post.get('country_code') or False

            dispatch_rpc('db', 'create_database',
                         [name, bool(post.get('demo')), lang, password, post['login'], country_code,
                          post['phone']])

            auth_api_key_model = {
                "user_id": 1,
                "create_uid": 2,
                "write_uid": 2,
                "name": name,
                "key": api_key,
                "create_date": datetime.datetime.now(),
                "write_date": datetime.datetime.now()
            }

            # insert api key to new database
            Service.insert_auth_api_key(dbname=name, data=auth_api_key_model)

            # get module installed in database
            modules = Service.get_modules_from_database(dbname=name, stateModule="installed")

            # country code could be = "False" which is actually True in python
            # request.session.authenticate(name, post['login'], password)
            # request.session.db = name

            return http.Response(
                json.dumps({
                    "api_key": api_key,
                    "modules": modules
                }),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            _logger.exception("Database creation error.")
            error = "Database creation error: %s" % (str(e) or repr(e))
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    # api stop database and change name ***_***
    @http.route('/web/databases/stop', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def stop_databases(self, dbname, privatekey, stringName, timestamp):
        # Check if the provided master password is valid
        # insecure = tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    db.dispatch('change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            # Check the database exists
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

            # Check if the provided master password is valid for database operations
            # db.check_super(MASTER_PASSWORD)

            # Construct new database name with '{random char}' suffix
            new_db_name = f"{dbname}_{stringName}"
            # Rename the database
            db.exp_rename(dbname, new_db_name)
            return http.Response(
                status=200,
                response=json.dumps(
                    {'success': True, 'message': f"Database {dbname} has been stopped and renamed to {new_db_name}"}
                ),
                content_type='application/json'
            )

        except Exception as e:
            error = f"Error stopping database: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )

    @http.route('/web/databases/modules', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def install_modules(self, privatekey, timestamp, dbname, moduleId):
        try:
            # check spam call api
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

            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_install()
                    return http.Response(
                        json.dumps({'message': f'install module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )

        except Exception as e:
            error = f"Error install module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/databases/modules', type='http', auth="none", methods=['PATCH'], csrf=False)
    @domain_validation_required
    def upgrade_modules(self, privatekey, timestamp, dbname, moduleId):
        try:
            # check spam call api
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
            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_upgrade()
                    return http.Response(
                        json.dumps({'message': f'upgrade module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )
        except Exception as e:
            error = f"Error upgrade module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/databases/modules', type='http', auth="none", methods=['DELETE'], csrf=False)
    @domain_validation_required
    def deactive_modules(self, privatekey, timestamp, dbname, moduleId):
        try:
            # check spam call api
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

            # Kết nối đến cơ sở dữ liệu được chỉ định
            with odoo.registry(dbname).cursor() as cr:
                env = odoo.api.Environment(cr, odoo.SUPERUSER_ID, {})
                module = env['ir.module.module'].search([['id', '=', moduleId]])
                if (module):
                    module.button_immediate_uninstall()
                    return http.Response(
                        json.dumps({'message': f'deactive module {module.shortdesc} successfully'}),
                        status=200,
                        mimetype='application/json'
                    )
                else:
                    return http.Response(
                        json.dumps({"Error": "Not found moudle id: " + moduleId}),
                        status=404,
                        mimetype='application/json'
                    )
        except Exception as e:
            error = f"Error deactive module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    # api get list role
    @http.route('/web/databases/roles', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_roless(self, dbname, privatekey, timestamp):
        try:
            # check spam call api
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
            # Lấy danh sách người dùng từ bảng res.users
            roles = Service.get_roles_from_database(dbname)

            return http.Response(
                json.dumps(roles),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            error = f"Error getting roles: {str(e)}"
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    # api get list activated modules
    @http.route('/web/databases/activated_modules', type='http', auth='none', methods=['GET'], csrf=False)
    @domain_validation_required
    def get_activated_moduless(self, dbname, timestamp, privatekey):

        try:
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

            modules = Service.get_modules_from_database(dbname, "installed")

            if modules is None:
                return http.Response(
                    json.dumps({"error": "No activated modules found"}),
                    status=404,
                    mimetype='application/json'
                )

            return http.Response(
                json.dumps(modules),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            error = f"Error getting activated modules: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    # api get list unactivated modules
    @http.route('/web/databases/unactivated_modules', type='http', auth='none', methods=['GET'], csrf=False)
    @domain_validation_required
    def get_unactivated_moduless(self, dbname, privatekey, timestamp):

        try:
            # check spam call api
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
            # Get modules with state 'uninstalled'
            uninstalled_modules = Service.get_modules_from_database(dbname, "uninstalled")

            # Get modules with state 'uninstallable'
            uninstallable_modules = Service.get_modules_from_database(dbname, "uninstallable")

            # Combine the results
            modules = uninstalled_modules + uninstallable_modules

            if modules is None:
                return http.Response(
                    json.dumps({"error": "No unactivated modules found"}),
                    status=404,
                    mimetype='application/json'
                )

            return http.Response(
                json.dumps(modules),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            error = f"Error getting unactivated modules: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/databases/companies', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_companiess(self, dbname, privatekey, timestamp):

        try:
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
            # Lấy danh sách người dùng từ bảng res.users
            companies = Service.get_companies_from_database(dbname)

            return http.Response(
                json.dumps(companies),
                status=200,
                mimetype='application/json'
            )
        except Exception as e:
            error = f"Error getting companies: {str(e)}"
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    # Change database name ****=> **_**
    @http.route('/web/databases/change_name', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def change_names(self, dbname, privatekey, newname, timestamp):
        # Check if the provided master password is valid
        # insecure = tools.config.verify_admin_password('admin')
        # if insecure and master_pwd:
        #    db.dispatch('change_admin_password', ["admin", master_pwd])

        try:
            # Check if the provided master password is valid for database operations
            # db.check_super(master_pwd)
            # Check if the database exists
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            if dbname not in db.list_dbs():
                return http.Response(
                    status=404,
                    response=json.dumps({'success': False, 'message': f"Database {dbname} not found"}),
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

            if not re.match(DBNAME_PATTERN, newname):
                raise Exception(
                    _('Invalid database name. Only alphanumerical characters, underscore, hyphen and dot are allowed.'))

            # Construct new database name with new_name
            new_db_name = f"{newname}"

            # Rename the database
            db.exp_rename(dbname, new_db_name)

            return http.Response(
                status=200,
                response=json.dumps(
                    {'success': True, 'message': f"Database {dbname} has been renamed to {new_db_name}"}),
                content_type='application/json'
            )

        except Exception as e:
            error = f"Error stopping database: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )

    @http.route('/web/databases/users', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def getuserss(self, dbname, privatekey, timestamp):
        try:
            # check spam call api
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
            # Lấy danh sách người dùng từ bảng res.users
            users = Service.get_users_from_database(dbname)

            return http.Response(
                json.dumps(users),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            error = f"Error getting users: {str(e)}"
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    @http.route('/web/databases/modules', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_moduless(self, dbname, privatekey, timestamp):
        try:
            # check timestamp
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

            module = Service.get_modules_from_database(dbname, None)

            return http.Response(
                json.dumps(module),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            error = f"Error getting module: {str(e)}"
            return http.Response(
                json.dumps({"error": error}),
                status=500,
                mimetype='application/json'
            )

    @http.route('/web/databases/invoices', type='http', auth="none", methods=['GET'], csrf=False)
    @domain_validation_required
    def get_invoicess(self, dbname, privatekey, timestamp):
        try:
            # check timestamp
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

                # Lấy danh sách người dùng từ bảng res.users
            invoices = Service.get_invoice_from_database(dbname)

            return http.Response(
                json.dumps(invoices),
                status=200,
                mimetype='application/json'
            )

        except Exception as e:
            error = "Error getting invoice: %s" % (str(e) or repr(e))
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    @http.route('/web/databases/duplicate', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def duplicates(self, timestamp, privatekey, dbname, new_name, neutralize_database=False):
        # insecure = odoo.tools.config.verify_admin_password('admin')
        # if insecure and MASTER_PASSWORD:
        #    dispatch_rpc('db', 'change_admin_password', ["admin", MASTER_PASSWORD])
        try:
            # check timestamp
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            if dbname not in db.list_dbs():
                return http.Response(json.dumps({"error": f'Not found database {dbname}'}), status=404,
                                     mimetype='application/json')

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

            if not re.match(DBNAME_PATTERN, new_name):
                raise Exception(
                    _('Invalid database name. Only alphanumerical characters, underscore, hyphen and dot are allowed.'))

            if new_name in db.list_dbs():
                return http.Response(json.dumps({"error": f'{new_name} database exist. Please choose another name'}),
                                     status=400, mimetype='application/json')

            dispatch_rpc('db', 'duplicate_database', [dbname, new_name, neutralize_database])

            if request.db == dbname:
                request.env.cr.close()  # duplicating a database leads to an unusable cursor

            return http.Response(json.dumps({"error": f'Duplicate database {dbname} successfully'}), status=200,
                                 mimetype='application/json')

        except Exception as e:
            _logger.exception("Database duplication error.")
            error = "Database duplication error: %s" % (str(e) or repr(e))
            return http.Response(json.dumps({"error": error}), status=500, mimetype='application/json')

    # api set account send email
    @http.route('/web/mail_server/setup_outgoing_mail', type='http', auth="none", methods=['POST'], csrf=False)
    @domain_validation_required
    def setup_outgoing_mails(self, timestamp, privatekey, dbname, name, email, password, isDefault,
                            smtp_encryption='ssl', smtp_port=465):

        try:
            # check spam call api
            if (is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )

            if dbname not in db.list_dbs():
                return http.Response(json.dumps({"error": f'Not found database {dbname}'}), status=404,
                                     mimetype='application/json')

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
                # Authenticate user and connect to database
            registry = odoo.modules.registry.Registry(dbname)
            with registry.cursor() as cr:
                env = odoo.api.Environment(cr, 1, {})

                # Set smtp_user and smtp_pass based on isDefault
                if isDefault.lower() == 'true':
                    # Use default admin credentials
                    smtp_user = 'admin'
                    smtp_pass = 'admin'

                else:
                    smtp_user = email
                    smtp_pass = password

                # Create a new mail server record
                mail_server_vals = {
                    'name': name,
                    'smtp_user': smtp_user,
                    'smtp_pass': smtp_pass,
                    'smtp_host': 'smtp.gmail.com',
                    'smtp_encryption': smtp_encryption,
                    'smtp_port': smtp_port,
                    'smtp_authentication': 'login'
                }
                mail_server = env['ir.mail_server'].create(mail_server_vals)

                # Check if Gmail server settings are valid
                mail_server._check_use_google_gmail_service()

                return http.Response(
                    status=200,
                    response=json.dumps({'success': True, 'message': 'Outgoing mail server setup successful'}),
                    content_type='application/json'
                )
        except Exception as e:
            error = f"Error setting up outgoing mail server: {str(e)}"
            return http.Response(
                status=500,
                response=json.dumps({'success': False, 'error': error}),
                content_type='application/json'
            )



