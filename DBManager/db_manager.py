from pymongo import MongoClient

class DB_Manager:
    def __init__(self):
        client = MongoClient(port=27017)
        self.db = client.minutes

    def insert_data(self, email):
        return self.db.emails.insert_one(email)

    def get_data(self):
        return self.db.emails.find()

    def get_one_query_data(self, q):
        return self.db.emails.find_one(q)

    def get_query_data(self, q):
        return self.db.emails.find(q)
