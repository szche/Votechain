FROM python:3.8.3
ADD requirements.txt ./
RUN pip install -r requirements.txt
ADD main.py ./
ADD voting_kit/ ./voting_kit/
ADD chain/ ./chain/
ADD airdrop.votechain/ ./
CMD ["python", "main.py", "committee"]
