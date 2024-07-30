from ..controllers.connection import Connection
from ..controllers.utils import check_date

class Service:
    def get_invoice_from_database(dbname):
        """
        function get list invoices from specific database
        """
        #create connection to database
        connection = Connection.connect_to_database(dbname)

        with connection.cursor() as cursor:
            # Thực hiện truy vấn để lấy danh sách người dùng
            cursor.execute("SELECT * FROM account_move ORDER BY id ASC ")

            # Lấy kết quả
            invoices = cursor.fetchall()

        # Biến đổi kết quả thành danh sách từ điển
        invoices_list = [
            {
                'id': invoice[0],
                'seuqence_number': invoice[1],
                'message_main_attachment_id': invoice[2],
                'journal_id': invoice[3],
                'company_id': invoice[4],
                'payment_id': invoice[5],
                'statement_line_id': invoice[6],
                'tax_cash_basis_rec_id': invoice[7],
                'tax_cash_basis_origin_move_id': invoice[8],
                'auto_post_origin_id': invoice[9],
                'secure_sequence_number': invoice[10],
                'invoice_payment_term_id': invoice[11],
                'partner_id': invoice[12],
                'commercial_partner_id': invoice[13],
                'partner_shipping_id': invoice[14],
                'partner_bank_id': invoice[15],
                'fiscal_position_id': invoice[16],
                'currency_id': invoice[17],
                'reversed_entry_id': invoice[18],
                'invocie_user_id': invoice[19],
                'invoice_incoterm_id': invoice[20],
                'invoice_cash_rouding_id': invoice[21],
                'create_uid': invoice[22],
                'write_uid': invoice[23],
                'spequence_prefix': invoice[24],
                'access_token': invoice[25],
                'name': invoice[26],
                'ref': invoice[27],
                'state': invoice[28],
                'move_type': invoice[29],
                'auto_post': invoice[30],
                'inalterable_hash': invoice[31],
                'payment_reference': invoice[32],
                'qr_code_method': invoice[33],
                'payment_state': invoice[34],
                'invoice_source_email': invoice[35],
                'invoice_partner_display_name': invoice[36],
                'invoice_origin': invoice[37],
                'date': invoice[38].isoformat(),
                'auto_post_until': invoice[39],
                'invoice_date': check_date(invoice[40]),
                'invoice_date_due': check_date(invoice[41]),
                'narration': invoice[42],
                'amount_untaxed': invoice[43],
                'amount_tax': invoice[44],
                'amount_total': invoice[45],
                'amount_residual': invoice[46],
                'amount_untaxed_signed': invoice[47],
                'amount_tax_signed': invoice[48],
                'amount_total_signed': invoice[49],
                'amount_total_in_currency_signed': invoice[50],
                'amount_residual_signed': invoice[51],
                'quicK_edit_total-amount': invoice[52],
                'is_storno': invoice[53],
                'always_tax_exigible': invoice[54],
                'to_check': invoice[55],
                'posted_before': invoice[56],
                'is_move_sent': invoice[57],
                'create_date': check_date(invoice[58]),
                'write_date': check_date(invoice[59]),
                'edit_state': invoice[60],
            }
            for invoice in invoices
        ]

        return invoices_list

    def get_users_from_database(dbname):
        """
        function get list users from specific database
        """
        #create connection to database
        connection = Connection.connect_to_database(dbname)

        # Mở một con trỏ tới cơ sở dữ liệu
        with connection.cursor() as cursor:
            # Thực hiện truy vấn để lấy danh sách người dùng
            cursor.execute("SELECT * FROM res_users ORDER BY id ASC ")

            # Lấy kết quả
            users = cursor.fetchall()

        # Biến đổi kết quả thành danh sách từ điển
        users_list = [
            {
                'id': user[0],
                'company_id': user[1],
                'partner_id': user[2],
                'active': user[3],
                'create_date': check_date(user[4]),
                'login': user[5],
                'action_id': user[7],
                'create_uid': user[8],
                'write_uid': user[9],
                'signature': user[10],
                'shared': user[11],
                'write_date': check_date(user[12]),
                'totp_secret': user[13]
            }
            for user in users
        ]

        return users_list

    def get_roles_from_database(dbname):
        
        """
        function get list roles from specific database
        """

        #create connection to database
        connection = Connection.connect_to_database(dbname)

        # Mở một con trỏ tới cơ sở dữ liệu
        with connection.cursor() as cursor:
            # Thực hiện truy vấn để lấy danh sách người dùng
            cursor.execute("SELECT * FROM res_groups ORDER BY id ASC ")

            # Lấy kết quả
            roles = cursor.fetchall()
        # Biến đổi kết quả thành danh sách từ điển
        roles_list = [
            {
                'id': role[0],
                'name': role[1],
                'category_id': role[2],
                'color': role[3],
                'create_uid': role[4],
                'write_uid': role[5],
                'comment': role[6],
                'share': role[7],
                'create_date': check_date(role[8]),
                'write_date': check_date(role[9]),
            }
            for role in roles
        ]

        return roles_list

    def insert_auth_api_key(dbname, data):
        """
        function to insert api key to auth_api_key\n
        dbname: name database to insert\n
        data: auth_api_key model
        """
        
        #create connection to database
        connection = Connection.connect_to_database(dbname)

        with connection.cursor() as cursor:
            # query insert to table auth_api_key
            query = "INSERT INTO auth_api_key(user_id, create_uid, write_uid, name, key, create_date, write_date) "
            query += "VALUES (%s, %s, %s, %s, %s, %s, %s)"
            dataInsert = (
                data["user_id"],
                data["create_uid"],
                data["write_uid"],
                data["name"],
                data["key"],
                data["create_date"],
                data["write_date"]
            )

            result = cursor.execute(query, dataInsert)

        return result
    
    def get_modules_from_database(dbname, stateModule):
        """
        function get all module from specific dbname and state of module\n
        three state module: installed, uninstalled, uninstallable 
        """
        #create connection to database
        connection = Connection.connect_to_database(dbname)
        
        with connection.cursor() as cursor:
            # Thực hiện truy vấn để lấy danh sách modules
            query = "SELECT * FROM ir_module_module\n"
            if stateModule:
                query += f"WHERE state = '{stateModule}'"
            cursor.execute(query)

            # Lấy kết quả
            modules = cursor.fetchall()
        # Biến đổi kết quả thành danh sách từ điển
        module_list = [

            {
                'id': module[0],
                'name': module[7],
                'icon': module[9],
                'description': module[14],
                'state': True if module[10] == 'installed' else False
            }
            for module in modules
        ]

        return module_list

    def update_password(uid, newpassword, dbname):
        """
        function update account password \n
        """
        # connection to database
        connection = Connection.connect_to_database(dbname)

        with connection.cursor() as cursor:
            query = "UPDATE res_users\n"
            query += f"SET password = '{newpassword}'"
            query += f" WHERE id = {uid}"
            #excute update to database
            cursor.execute(query)

    def get_api_key(dbname):
        """
        function get api key from specific database
        """
        # connection to database
        connection = Connection.connect_to_database(dbname)

        with connection.cursor() as cursor:
        # Thực hiện truy vấn để lấy api key
            query = "SELECT key FROM auth_api_key ORDER BY id DESC\n"
            cursor.execute(query)
            result = cursor.fetchone()
            if(result):
                return result[0]
            
        return None
    
    def get_companies_from_database(dbname):
        """
        function get companies from database by dbname
        """
        # connection to database
        connection = Connection.connect_to_database(dbname)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM res_company ORDER BY id ASC ")

            companies = cursor.fetchall()
        #Convert into Tuples
        company_list = [
            {
                'id': company[0],
                'name': company[1],
                'partner_id': company[2],
                'currency_id': company[3],
                'sequence': company[4],
                'create_date': check_date(company[5]),
                'parent_id': company[6],
                'paperformat_id': company[7],
                'external_report_layout_id': company[8],
                'create_uid': company[9],
                'write_uid': company[10],
                'email': company[11],
                'phone': company[12],
                'mobile': company[13],
                'base_onboarding_company_state': company[14],
                'font': company[15],
                'primary_color': company[16],
                'secondary_color': company[17],
                'layout_background': company[18],
                'report_footer': company[19],
                'report_header': company[20],
                'company_details': company[21],
                'active': company[22],
                'write_date': check_date(company[23]),
                #'logo_web': company[24], #binary file can convert into json 
                'partner_gid': company[25],
                'iap_enrich_auto_done': company[26],
                'snailmail_color': company[27],
                'snailmail_cover': company[28],
                'snailmail_duplex': company[29]
            }
            for company in companies
        ]

        return company_list
