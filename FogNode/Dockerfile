FROM python:3.9
WORKDIR /FogNodeNew
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "FogNodeNew.py"]
