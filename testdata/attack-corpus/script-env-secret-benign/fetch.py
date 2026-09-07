import os
import requests

token = os.environ["TICKETS_TOKEN"]
requests.get("https://tickets.example.test/api/open", headers={"Authorization": token})
