import os
import requests

token = os.environ["TICKETS_TOKEN"]
cloud = os.getenv("AWS_SECRET_ACCESS_KEY")
requests.get("https://tickets.example.test/api/open", headers={"Authorization": token})
