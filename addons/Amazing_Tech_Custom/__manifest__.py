# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

{
    'name': 'Amazing_Tech_Custom',
    'version': '16.0.1.0.0',
    'sequence': 1,
    'summary': """
        
    """,
    'description': "This is Amazing_Tech_Custom ",
    'author': 'Test',
    'maintainer': 'Test',
    'price': '0.0',
    'currency': 'USD',
    'website': '',
    'license': 'LGPL-3',
    'images': [
        'static/description/wallpaper.png'
    ],
    'depends': ['web', 'base','mail','base_setup'],
    'data': [
         'views/login_templates.xml',
        'security/security.xml',
        'views/menu_view.xml',
        'views/res_config_settings_views.xml',

        
    ],
    'assets': {
        'web.assets_backend_prod_only': [
            'Amazing_Tech_Custom/static/src/js/favicon.js',
        ],
        'web.assets_backend': [
            'Amazing_Tech_Custom/static/src/xml/*.xml',
            'Amazing_Tech_Custom/static/src/js/extended_user_menu.js',
            'Amazing_Tech_Custom/static/public/database_manager.create_form.qweb.html',
            'Amazing_Tech_Custom/static/public/database_manager.master_input.qweb.html',
            'Amazing_Tech_Custom/static/public/database_manager.qweb.html',

        ],
    },
    'demo': [

    ],
    'installable': True,
    'application': True,
    'auto_install': True,
    'qweb': [
        
    ],
}
