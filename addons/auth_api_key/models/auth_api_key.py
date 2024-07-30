# Copyright 2018 ACSONE SA/NV
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).

from odoo import _, api, fields, models, tools
from odoo.exceptions import AccessError, ValidationError
from odoo.tools import consteq
import logging
_logger = logging.getLogger(__name__)
class AuthApiKey(models.Model):
    _name = "auth.api.key"
    _description = "API Key"

    name = fields.Char(required=True)
    key = fields.Char(
        required=True,
        help="""The API key. Enter a dummy value in this field if it is
        obtained from the server environment configuration.""",
    )
    user_id = fields.Many2one(
        comodel_name="res.users",
        string="User",
        required=True,
        help="""The user used to process the requests authenticated by
        the api key""",
    )

    _sql_constraints = [("name_uniq", "unique(name)", "Api Key name must be unique.")]

    @api.model
    def _retrieve_api_key(self, key):
        print("vo day xem database")
        return self.browse(self._retrieve_api_key_id(key))

    @api.model
    @tools.ormcache("key")
    def _retrieve_api_key_id(self, key):
        print("ham check database")
        if not self.env.user.has_group("base.group_system"):
            raise AccessError(_("User is not allowed"))
        for api_key in self.search([]):
            print("so sanh 2 api key")
            print(consteq(key, api_key.key))

            _logger.info(consteq(key, api_key.key))
            _logger.info("key chuyen vo %s",key)
            _logger.info(api_key.key)
            if api_key.key and consteq(key, api_key.key):
                print(api_key.id)
                return api_key.id
        raise ValidationError(_("The key %s is not allowed") % key)

    @api.model
    @tools.ormcache("key")
    def _retrieve_uid_from_api_key(self, key):
        return self._retrieve_api_key(key).user_id.id

    def _clear_key_cache(self):
        self._retrieve_api_key_id.clear_cache(self.env[self._name])
        self._retrieve_uid_from_api_key.clear_cache(self.env[self._name])

    @api.model_create_multi
    def create(self, vals_list):
        records = super(AuthApiKey, self).create(vals_list)
        if any(["key" in vals or "user_id" in vals for vals in vals_list]):
            self._clear_key_cache()
        return records

    def write(self, vals):
        super(AuthApiKey, self).write(vals)
        if "key" in vals or "user_id" in vals:
            self._clear_key_cache()
        return True
