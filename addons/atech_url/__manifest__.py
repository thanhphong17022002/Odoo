{
    'name': 'URL Redirect',
    'version': '1.2.1',
    'summary': 'Hide URL',
    'sequence': 30,
    'description': """
        Just about hiding URL""",
    'author': 'Son Bui ',
    'company': 'Cong ty Co Ma',
    'website': 'https://www.website.com',
    'category': 'Customization',
    'depends': ['web','base'],
    'data': [
      'views/custom_page.xml'
    ],
    "assets": {
        "web.assets_frontend": [
            'atech_url/static/src/scss/layout.scss'
        ],
        "web.assets_backend": [

        ],
    },

    'application': True,
    'auto_install': False,
    'auto_upgrade': False,
}
