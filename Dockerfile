
FROM python:3.8-slim

WORKDIR /app
COPY module/dremio_module_register.py dremio_module_register.py
COPY module/utils.py utils.py
ENV FORMAT "dummy format"
ENV DATAPATH "dummy datapath"
ENV NAME "dummy data asset name"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir pyyaml

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements.txt

ENTRYPOINT ["python3"]
CMD ["dremio_module_register.py"]
