# compiles the configurator to an executable
# docker cp it out when done
FROM python:3.7-slim
COPY ./requirements.txt /tmp/
RUN apt update && apt install -y git build-essential python3-dev
RUN python3 -m pip install -r /tmp/requirements.txt
RUN python3 -m pip install nuitka
COPY appliancecfg.py /pyappliancecfg/
RUN chmod +x /pyappliancecfg/appliancecfg.py
RUN cd /pyappliancecfg && \
    python -m nuitka --recurse-all --standalone appliancecfg.py && \
    cd /pyappliancecfg/appliancecfg.dist/ && \
    tar -czf appliancecfg.tar.gz appliancecfg _hashlib.so  _posixsubprocess.so  _random.so  _socket.so  libpython3.7m.so.1.0  math.so  select.so
