# Use the official Python image from Docker Hub
FROM python:3.8-slim

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        build-essential \
        libpq-dev \
        libxml2-dev \
        libxslt1-dev \
        libldap2-dev \
        libsasl2-dev \
        libssl-dev \
        libxext6 \
        libjpeg-dev \
        zlib1g-dev \
        libfreetype6-dev \
        liblcms2-dev \
        libwebp-dev \
        libtiff5-dev \
        libopenjp2-7-dev \
        libjpeg62-turbo-dev \
        wget \
        curl \
        unzip 

COPY ./entrypoint.sh /
COPY ./odoo.conf /etc/odoo/
COPY setup/odoo /usr/bin/odoo
COPY odoo-bin /opt/odoo/odoo-bin
COPY wait-for-psql.py /usr/local/bin/wait-for-psql.py
COPY requirements.txt /
RUN chmod +x /entrypoint.sh \
    && chmod +x /usr/local/bin/wait-for-psql.py \
    && chmod +x /usr/bin/odoo
# Set working directory
WORKDIR /app
COPY . /app
# Install Odoo dependencies
RUN pip install -r requirements.txt --target=/usr/lib/python3/dist-packages
RUN mkdir -p /usr/lib/python3/dist-packages/odoo
RUN chmod +x /usr/lib/python3/dist-packages/odoo
RUN cp -r /app/odoo /usr/lib/python3/dist-packages/
ENV PYTHONPATH="${PYTHONPATH}:/usr/lib/python3/dist-packages/"

# Expose Odoo port
EXPOSE 8069 8071 8072
# Start Odoo
# ENTRYPOINT ["/entrypoint.sh"]
# CMD ["python", "/app/odoo-bin"]
CMD ["odoo", "--config=/etc/odoo/odoo.conf" ]
# , "-c", "odoo.conf"
