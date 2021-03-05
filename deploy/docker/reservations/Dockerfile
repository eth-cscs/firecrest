from f7t-base

ADD deploy/docker/reservations/requirements.txt deps/requirements.txt
RUN pip3 install -r deps/requirements.txt

ADD src/reservations/reservations.py reservations.py
ADD src/common/cscs_api_common.py cscs_api_common.py

ENTRYPOINT ["python3"]
CMD ["reservations.py"]