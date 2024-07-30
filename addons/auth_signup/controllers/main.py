# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.
import logging
import werkzeug
import datetime
from werkzeug.urls import url_encode
import json

from odoo import http, tools, _
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.addons.web.controllers.home import ensure_db, Home, SIGN_UP_REQUEST_PARAMS, LOGIN_SUCCESSFUL_PARAMS
from odoo.addons.base_setup.controllers.main import BaseSetup
from odoo.exceptions import UserError
from odoo.http import request
from odoo.http import content_disposition, dispatch_rpc, request, Response

_logger = logging.getLogger(__name__)

LOGIN_SUCCESSFUL_PARAMS.add('account_created')


class AuthSignupHome(Home):

    @http.route()
    def web_login(self, *args, **kw):
        ensure_db()
        response = super().web_login(*args, **kw)
        response.qcontext.update(self.get_auth_signup_config())
        if request.session.uid:
            if request.httprequest.method == 'GET' and request.params.get('redirect'):
                # Redirect if already logged in and redirect param is present
                return request.redirect(request.params.get('redirect'))
            # Add message for non-internal user account without redirect if account was just created
            if response.location == '/web/login_successful' and kw.get('confirm_password'):
                return request.redirect_query('/web/login_successful', query={'account_created': True})
        return response

    @http.route('/web/signup', type='http', auth='public', website=True, sitemap=False)
    def web_auth_signup(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()

        if not qcontext.get('token') and not qcontext.get('signup_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            try:
                self.do_signup(qcontext)
                # Send an account creation confirmation email
                User = request.env['res.users']
                user_sudo = User.sudo().search(
                    User._get_login_domain(qcontext.get('login')), order=User._get_login_order(), limit=1
                )
                template = request.env.ref('auth_signup.mail_template_user_signup_account_created', raise_if_not_found=False)
                if user_sudo and template:
                    template.sudo().send_mail(user_sudo.id, force_send=True)
                return self.web_login(*args, **kw)
            except UserError as e:
                qcontext['error'] = e.args[0]
            except (SignupError, AssertionError) as e:
                if request.env["res.users"].sudo().search([("login", "=", qcontext.get("login"))]):
                    qcontext["error"] = _("Another user is already registered using this email address.")
                else:
                    _logger.error("%s", e)
                    qcontext['error'] = _("Could not create a new account.")

        elif 'signup_email' in qcontext:
            user = request.env['res.users'].sudo().search([('email', '=', qcontext.get('signup_email')), ('state', '!=', 'new')], limit=1)
            if user:
                return request.redirect('/web/login?%s' % url_encode({'login': user.login, 'redirect': '/web'}))

        response = request.render('auth_signup.signup', qcontext)
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
        return response
    '''
    @http.route('/web/reset_password', type='http', auth='public', website=True, sitemap=False)
    def web_auth_reset_password(self, *args, **kw):
        qcontext = self.get_auth_signup_qcontext()

        if not qcontext.get('token') and not qcontext.get('reset_password_enabled'):
            raise werkzeug.exceptions.NotFound()

        if 'error' not in qcontext and request.httprequest.method == 'POST':
            try:
                if qcontext.get('token'):
                    self.do_signup(qcontext)
                    return self.web_login(*args, **kw)
                else:
                    login = qcontext.get('login')
                    assert login, _("No login provided.")
                    _logger.info(
                        "Password reset attempt for <%s> by user <%s> from %s",
                        login, request.env.user.login, request.httprequest.remote_addr)
                    request.env['res.users'].sudo().reset_password(login)
                    qcontext['message'] = _("Password reset instructions sent to your email")
            except UserError as e:
                qcontext['error'] = e.args[0]
            except SignupError:
                qcontext['error'] = _("Could not reset your password")
                _logger.exception('error when resetting password')
            except Exception as e:
                qcontext['error'] = str(e)

        elif 'signup_email' in qcontext:
            user = request.env['res.users'].sudo().search([('email', '=', qcontext.get('signup_email')), ('state', '!=', 'new')], limit=1)
            if user:
                return request.redirect('/web/login?%s' % url_encode({'login': user.login, 'redirect': '/web'}))

        response = request.render('auth_signup.reset_password', qcontext)
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
        return response
    '''

    #API Forgot password api
    @http.route('/web/reset_password', type='http', auth='public', website=True, sitemap=False, csrf=False)
    def web_auth_forgot_password(self, *args, **kw):  #the api required timestaps
       
        qcontext = self.get_auth_signup_qcontext()

        if not qcontext.get('token') and not qcontext.get('reset_password_enabled'):
            raise werkzeug.exceptions.NotFound()

        if qcontext.get('token') and request.httprequest.method == 'GET':
            return http.Response(
                        status=200,
                    )
        
        if 'error' not in qcontext and request.httprequest.method == 'POST':
            timestamp = qcontext.get('timestamp')
            #check timestamp
            if(self.is_greater_than_3_minutes(timestamp) == False):
                return http.Response(
                    json.dumps({"error": "Invalid time"}),
                    status=400,
                    content_type='application/json'
                )
            if qcontext.get('token'):
                if not qcontext.get('password') or not qcontext.get('confirm_password'):
                    qcontext['error'] = _("No password provided")
                else:
                    self.do_signup(qcontext)
                    return http.Response(
                        status=200,
                        response=json.dumps({'success': True, 'message': "Login Successfully"}),
                        content_type='application/json'
                    )
            else:
                login = qcontext.get('login')
                #assert login, _("No login provided.")
                if not login:
                    qcontext['error'] = _("No login provided")
                else: 
                    _logger.info(
                        "Password reset attempt for <%s> by user <%s> from %s",
                        login, request.env.user.login, request.httprequest.remote_addr
                    )
                    request.env['res.users'].sudo().reset_password(login)
                    qcontext['message'] = _("Password reset instructions sent to your email")
                    return http.Response(
                        status=200,
                        response=json.dumps({'success': True, 'message': qcontext['message']}),
                        content_type='application/json'
                    ) 

        if 'error' in qcontext:
            return http.Response(
                status=400,
                response=json.dumps({'success': False, 'message': qcontext['error']}),
                content_type='application/json'
            )
        try:
            raise UserError(qcontext['error'])
        except UserError as e:
            response = http.Response(
                status=400,
                response=json.dumps({'success': False, 'message': f"(User Error) {e.args[0]}"}),
                content_type='application/json'
            )
        except SignupError:
            _logger.error('Error when resetting password')
            response = http.Response(
                status=400,
                response=json.dumps({'success': False, 'message': _("Could not reset your password")}),
                content_type='application/json'
            )
        except Exception as e:
            response = http.Response(
                status=500,
                response=json.dumps({'success': False, 'message': str(e)}),
                content_type='application/json'
            )
        return response
    
    
    def get_auth_signup_config(self):
        """retrieve the module config (which features are enabled) for the login page"""

        get_param = request.env['ir.config_parameter'].sudo().get_param
        return {
            'disable_database_manager': not tools.config['list_db'],
            'signup_enabled': request.env['res.users']._get_signup_invitation_scope() == 'b2c',
            'reset_password_enabled': get_param('auth_signup.reset_password') == 'True',
        }

    def get_auth_signup_qcontext(self):
        """ Shared helper returning the rendering context for signup and reset password """
        qcontext = {k: v for (k, v) in request.params.items() if k in SIGN_UP_REQUEST_PARAMS}
        qcontext.update(self.get_auth_signup_config())
        if not qcontext.get('token') and request.session.get('auth_signup_token'):
            qcontext['token'] = request.session.get('auth_signup_token')
        if qcontext.get('token'):
            try:
                # retrieve the user info (name, login or email) corresponding to a signup token
                token_infos = request.env['res.partner'].sudo().signup_retrieve_info(qcontext.get('token'))
                for k, v in token_infos.items():
                    qcontext.setdefault(k, v)
            except:
                qcontext['error'] = _("Invalid signup token")
                qcontext['invalid_token'] = True
        return qcontext

    def _prepare_signup_values(self, qcontext):
        values = { key: qcontext.get(key) for key in ('login', 'name', 'password') }
        if not values:
            raise UserError(_("The form was not properly filled in."))
        if values.get('password') != qcontext.get('confirm_password'):
            raise UserError(_("Passwords do not match; please retype them."))
        supported_lang_codes = [code for code, _ in request.env['res.lang'].get_installed()]
        lang = request.context.get('lang', '')
        if lang in supported_lang_codes:
            values['lang'] = lang
        return values

    def do_signup(self, qcontext):
        """ Shared helper that creates a res.partner out of a token """
        values = self._prepare_signup_values(qcontext)
        self._signup_with_values(qcontext.get('token'), values)
        request.env.cr.commit()

    def _signup_with_values(self, token, values):
        login, password = request.env['res.users'].sudo().signup(values, token)
        request.env.cr.commit()     # as authenticate will use its own cursor we need to commit the current transaction
        pre_uid = request.session.authenticate(request.db, login, password)
        if not pre_uid:
            raise SignupError(_('Authentication Failed.'))
    
    def is_greater_than_3_minutes(timestamp):
        # Chuyển đổi timestamp thành đối tượng datetime
        timestamp_datetime = datetime.fromtimestamp(timestamp)

        # Lấy thời gian hiện tại
        current_time = datetime.now()

        # Tính khoảng cách thời gian giữa timestamp và hiện tại
        time_difference = current_time - timestamp_datetime

        # So sánh với 3 phút
        if time_difference >= datetime.timedelta(minutes=3):
            return True
        else:
            return False

class AuthBaseSetup(BaseSetup):
    @http.route('/base_setup/data', type='json', auth='user')
    def base_setup_data(self, **kwargs):
        res = super().base_setup_data(**kwargs)
        res.update({'resend_invitation': True})
        return res
