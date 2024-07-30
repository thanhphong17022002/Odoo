from odoo.sql_db import connection_info_for, db_connect

# function to connect to database above db name
class Connection:
    def connect_to_database(dbname):
        # check database exist
        #if not http.db_filter([dbname]):
        #    return BadRequest("Database not found")

        # Thiết lập thông tin kết nối cho cơ sở dữ liệu
        db_name, connection_info = connection_info_for(dbname)

        # Kết nối tới cơ sở dữ liệu
        connection = db_connect(db_name)

        return connection