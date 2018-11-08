from pymongo import MongoClient
from datetime import datetime

class DB_Manager:
    def __init__(self):
        client = MongoClient(port=27017)
        self.db = client.minutes

    def insert_data(self, email):
        return self.db.emails.insert_one(email)

    def get_data(self):
        return self.db.emails.find()

    def get_min_time(self, thread_id):
        result = self.db.emails.find({'thread_id' : thread_id}).sort([('time_stamp', 1)]).limit(1)
        time_stamp = result[0]['time_stamp']
        return datetime.utcfromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S')

    def get_max_time(self, thread_id):
        result = self.db.emails.find({'thread_id' : thread_id}).sort([('time_stamp', -1)]).limit(1)
        time_stamp = result[0]['time_stamp']
        return datetime.utcfromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S')

    def get_thread_numbers(self, course, year):
        result = self.db.emails.find({'course' : course, 'year' : year})
        list = []
        for r in result:
            list.append(r['thread_id'])
        return set(list)

    def get_one_query_data(self, q):
        return self.db.emails.find_one(q)

    def get_query_data(self, q):
        return self.db.emails.find(q)
