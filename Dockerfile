FROM python:3.8.3
ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD main.py ./
ADD chain/ ./chain/
ADD data/ ./data/
CMD ["python", "main.py", "committee"]
